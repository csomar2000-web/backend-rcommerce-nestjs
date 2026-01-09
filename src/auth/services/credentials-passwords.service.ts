import {
    Injectable,
    UnauthorizedException,
    BadRequestException,
    ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { SessionsDevicesService } from './sessions-devices.service';
import { MailService } from '../../mail/mail.service';
import { SecurityAbuseService } from './security-abuse.service';
import { AuthProvider, MfaType } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as speakeasy from 'speakeasy';

const RESET_TOKEN_TTL_HOURS = 1;
const BCRYPT_ROUNDS = 12;

const PASSWORD_REGEX =
    /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

const MFA_KEY = Buffer.from(process.env.MFA_SECRET_KEY!, 'hex');


function assertStrongPassword(password: string) {
    if (!PASSWORD_REGEX.test(password)) {
        throw new BadRequestException('Password too weak');
    }
}

function decrypt(data: {
    cipherText: string;
    iv: string;
    authTag: string;
}) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        MFA_KEY,
        Buffer.from(data.iv, 'base64'),
    );

    decipher.setAuthTag(Buffer.from(data.authTag, 'base64'));

    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(data.cipherText, 'base64')),
        decipher.final(),
    ]);

    return decrypted.toString('utf8');
}

@Injectable()
export class CredentialsPasswordsService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly sessions: SessionsDevicesService,
        private readonly mail: MailService,
        private readonly abuse: SecurityAbuseService,
    ) { }

    async login(params: {
        email: string;
        password: string;
        ipAddress: string;
        userAgent: string;
    }) {
        const email = params.email.toLowerCase().trim();

        await this.abuse.assertLoginAllowed({
            email,
            ipAddress: params.ipAddress,
        });

        const account = await this.prisma.authAccount.findFirst({
            where: {
                provider: AuthProvider.LOCAL,
                user: { email },
            },
            include: { user: true },
        });

        if (!account || !account.passwordHash || !account.verifiedAt) {
            await this.abuse.recordFailedLogin({
                email,
                ipAddress: params.ipAddress,
            });
            throw new UnauthorizedException('Invalid credentials');
        }

        const passwordValid = await bcrypt.compare(
            params.password,
            account.passwordHash,
        );

        if (!passwordValid) {
            await this.abuse.recordFailedLogin({
                email,
                ipAddress: params.ipAddress,
            });
            throw new UnauthorizedException('Invalid credentials');
        }

        await this.abuse.clearLoginFailures(email, params.ipAddress);

        const session = await this.sessions.createSession({
            userId: account.user.id,
            ipAddress: params.ipAddress,
            userAgent: params.userAgent,
        });

        const mfaFactor = await this.prisma.mfaFactor.findFirst({
            where: {
                userId: account.user.id,
                type: MfaType.TOTP,
                revokedAt: null,
                verifiedAt: { not: null },
            },
        });

        if (mfaFactor) {
            return {
                mfaRequired: true,
                sessionId: session.id,
                userId: account.user.id,
            };
        }

        return {
            userId: account.user.id,
            sessionId: session.id,
        };
    }

    async verifyMfaCode(params: {
        userId: string;
        sessionId: string;
        code: string;
    }) {
        const factor = await this.prisma.mfaFactor.findFirst({
            where: {
                userId: params.userId,
                type: MfaType.TOTP,
                revokedAt: null,
                verifiedAt: { not: null },
            },
        });

        if (!factor) {
            throw new UnauthorizedException('Invalid MFA code');
        }

        const secret = decrypt({
            cipherText: factor.secretCipher,
            iv: factor.secretIv,
            authTag: factor.secretTag,
        });

        const valid = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token: params.code,
            window: 1,
        });

        if (!valid) {
            throw new UnauthorizedException('Invalid MFA code');
        }

        await this.prisma.mfaFactor.update({
            where: { id: factor.id },
            data: { lastUsedAt: new Date() },
        });

        return { success: true };
    }

    async requestPasswordReset(params: {
        email: string;
        ipAddress: string;
        userAgent: string;
    }) {
        const email = params.email.toLowerCase().trim();

        await this.abuse.assertSensitiveActionAllowed({
            identifier: `password_reset:${email}`,
            type: 'PASSWORD_RESET',
        });

        const user = await this.prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            return { success: true };
        }

        const rawToken = crypto.randomBytes(48).toString('hex');
        const hashedToken = this.hash(rawToken);

        await this.prisma.passwordReset.create({
            data: {
                userId: user.id,
                token: hashedToken,
                expiresAt: new Date(
                    Date.now() + RESET_TOKEN_TTL_HOURS * 60 * 60 * 1000,
                ),
            },
        });

        await this.mail.sendPasswordReset(
            user.email,
            `${process.env.FRONTEND_URL}/reset-password?token=${rawToken}`,
        );

        return { success: true };
    }

    async confirmPasswordReset(params: {
        token: string;
        newPassword: string;
        ipAddress: string;
        userAgent: string;
    }) {
        assertStrongPassword(params.newPassword);

        const hashedToken = this.hash(params.token);

        const reset = await this.prisma.passwordReset.findFirst({
            where: {
                token: hashedToken,
                usedAt: null,
                expiresAt: { gt: new Date() },
            },
        });

        if (!reset) {
            throw new BadRequestException('Invalid or expired token');
        }

        const passwordHash = await bcrypt.hash(
            params.newPassword,
            BCRYPT_ROUNDS,
        );

        await this.prisma.$transaction([
            this.prisma.authAccount.updateMany({
                where: {
                    userId: reset.userId,
                    provider: AuthProvider.LOCAL,
                },
                data: { passwordHash },
            }),
            this.prisma.passwordReset.update({
                where: { id: reset.id },
                data: { usedAt: new Date() },
            }),
            this.prisma.session.updateMany({
                where: { userId: reset.userId },
                data: { revokedAt: new Date() },
            }),
        ]);

        return { success: true };
    }

    async changePassword(params: {
        userId: string;
        currentPassword: string;
        newPassword: string;
        ipAddress: string;
        userAgent: string;
    }) {
        assertStrongPassword(params.newPassword);

        const account = await this.prisma.authAccount.findFirst({
            where: {
                userId: params.userId,
                provider: AuthProvider.LOCAL,
            },
        });

        if (!account || !account.passwordHash) {
            throw new ForbiddenException();
        }

        const valid = await bcrypt.compare(
            params.currentPassword,
            account.passwordHash,
        );

        if (!valid) {
            throw new UnauthorizedException('Invalid password');
        }

        const newHash = await bcrypt.hash(
            params.newPassword,
            BCRYPT_ROUNDS,
        );

        await this.prisma.$transaction([
            this.prisma.authAccount.update({
                where: { id: account.id },
                data: { passwordHash: newHash },
            }),
            this.prisma.session.updateMany({
                where: { userId: params.userId },
                data: { revokedAt: new Date() },
            }),
        ]);

        return { success: true };
    }

    private hash(value: string): string {
        return crypto.createHash('sha256').update(value).digest('hex');
    }
}
