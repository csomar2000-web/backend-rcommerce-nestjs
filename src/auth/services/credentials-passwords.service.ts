import {
    Injectable,
    UnauthorizedException,
    BadRequestException,
    ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { SessionsDevicesService } from './sessions-devices.service';
import { MailService } from '../../mail/mail.service';
import { AuthProvider, MfaType } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as speakeasy from 'speakeasy';

const RESET_TOKEN_TTL_HOURS = 1;
const PASSWORD_MIN_LENGTH = 8;
const BCRYPT_ROUNDS = 12;

@Injectable()
export class CredentialsPasswordsService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly sessions: SessionsDevicesService,
        private readonly mail: MailService,
    ) { }

    async login(params: {
        email: string;
        password: string;
        ipAddress: string;
        userAgent: string;
    }) {
        const email = params.email.toLowerCase().trim();

        const account = await this.prisma.authAccount.findFirst({
            where: {
                provider: AuthProvider.LOCAL,
                user: { email },
            },
            include: { user: true },
        });

        if (!account || !account.passwordHash) {
            throw new UnauthorizedException('Invalid credentials');
        }

        if (!account.verifiedAt) {
            throw new ForbiddenException('Email not verified');
        }

        const passwordValid = await bcrypt.compare(
            params.password,
            account.passwordHash,
        );

        if (!passwordValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

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
                revokedAt: null,
                verifiedAt: { not: null },
            },
        });

        if (!factor) {
            throw new UnauthorizedException('MFA not enabled');
        }

        const valid = speakeasy.totp.verify({
            secret: factor.secretHash,
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

        const user = await this.prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            return { success: true };
        }

        const token = crypto.randomBytes(48).toString('hex');

        await this.prisma.passwordReset.create({
            data: {
                userId: user.id,
                token,
                expiresAt: new Date(
                    Date.now() + RESET_TOKEN_TTL_HOURS * 60 * 60 * 1000,
                ),
            },
        });

        await this.mail.sendPasswordReset(
            user.email,
            `${process.env.FRONTEND_URL}/reset-password?token=${token}`,
        );

        return { success: true };
    }

    async confirmPasswordReset(params: {
        token: string;
        newPassword: string;
        ipAddress: string;
        userAgent: string;
    }) {
        if (params.newPassword.length < PASSWORD_MIN_LENGTH) {
            throw new BadRequestException('Password too weak');
        }

        const reset = await this.prisma.passwordReset.findFirst({
            where: {
                token: params.token,
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
        if (params.newPassword.length < PASSWORD_MIN_LENGTH) {
            throw new BadRequestException('Password too weak');
        }

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
}
