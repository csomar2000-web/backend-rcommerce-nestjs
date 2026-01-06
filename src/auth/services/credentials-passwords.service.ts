import {
    Injectable,
    UnauthorizedException,
    BadRequestException,
    ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { TokenService } from '../token/token.service';
import { SessionsDevicesService } from './sessions-devices.service';
import { SecurityAbuseService } from './security-abuse.service';
import { MailService } from '../../mail/mail.service';
import {
    AuthProvider,
    MfaType,
    MfaChallengeReason,
} from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

const RESET_TOKEN_TTL_HOURS = 1;
const PASSWORD_MIN_LENGTH = 10;

@Injectable()
export class CredentialsPasswordsService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly tokenService: TokenService,
        private readonly sessions: SessionsDevicesService,
        private readonly abuse: SecurityAbuseService,
        private readonly mail: MailService,
    ) { }

    /* ------------------------------------------------------------------ */
    /* LOGIN (MFA-AWARE)                                                   */
    /* ------------------------------------------------------------------ */

    async login(params: {
        email: string;
        password: string;
        ipAddress: string;
        userAgent: string;
        deviceId?: string;
        deviceName?: string;
    }) {
        const email = params.email.toLowerCase().trim();

        await this.abuse.assertLoginAllowed({ identifier: email });

        const account = await this.prisma.authAccount.findFirst({
            where: {
                provider: AuthProvider.LOCAL,
                user: { email },
            },
            include: { user: true },
        });

        if (!account || !account.passwordHash) {
            await this.recordLoginFailure(email, params);
            throw new UnauthorizedException('Invalid credentials');
        }

        if (!account.isVerified) {
            throw new ForbiddenException('Email not verified');
        }

        const valid = await bcrypt.compare(
            params.password,
            account.passwordHash,
        );

        if (!valid) {
            await this.recordLoginFailure(email, params);
            throw new UnauthorizedException('Invalid credentials');
        }

        await this.abuse.clearLoginFailures(email);

        /**
         * 1️⃣ Create session (but DO NOT issue tokens yet)
         */
        const session = await this.sessions.createSession({
            userId: account.user.id,
            ipAddress: params.ipAddress,
            userAgent: params.userAgent,
            deviceId: params.deviceId,
            deviceName: params.deviceName,
        });

        /**
         * 2️⃣ Check if MFA is enabled
         */
        const mfaFactor = await this.prisma.mfaFactor.findFirst({
            where: {
                userId: account.user.id,
                isEnabled: true,
                revokedAt: null,
            },
        });

        if (mfaFactor) {
            /**
             * 3️⃣ Create MFA challenge (idempotent)
             */
            await this.prisma.mfaChallenge.upsert({
                where: {
                    sessionId_factorType: {
                        sessionId: session.id,
                        factorType: MfaType.TOTP,
                    },
                },
                update: {
                    satisfied: false,
                    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
                    reason: MfaChallengeReason.LOGIN,
                },
                create: {
                    userId: account.user.id,
                    sessionId: session.id,
                    factorType: MfaType.TOTP,
                    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
                    reason: MfaChallengeReason.LOGIN,
                },
            });

            return {
                mfaRequired: true,
                reason: MfaChallengeReason.LOGIN,
                sessionId: session.id,
            };
        }

        /**
         * 4️⃣ MFA not enabled → issue tokens
         */
        const accessToken = this.tokenService.generateAccessToken(
            account.user.id,
            'CUSTOMER',
            session.id,
        );

        const { refreshToken } =
            await this.tokenService.generateRefreshToken({
                userId: account.user.id,
                sessionId: session.id,
                ipAddress: params.ipAddress,
                userAgent: params.userAgent,
            });

        await this.mail.sendSecurityAlert(account.user.email, {
            type: 'NEW_DEVICE_LOGIN',
            ipAddress: params.ipAddress,
            userAgent: params.userAgent,
        });

        await this.prisma.userAuditLog.create({
            data: {
                userId: account.user.id,
                eventType: 'AUTH',
                eventAction: 'LOGIN_SUCCESS',
                ipAddress: params.ipAddress,
                userAgent: params.userAgent,
                success: true,
            },
        });

        return { accessToken, refreshToken };
    }

    /* ------------------------------------------------------------------ */
    /* PASSWORD RESET (UNCHANGED, BUT SECURE)                              */
    /* ------------------------------------------------------------------ */

    async requestPasswordReset(params: {
        email: string;
        ipAddress: string;
        userAgent: string;
    }) {
        const email = params.email.toLowerCase().trim();

        await this.abuse.assertSensitiveActionAllowed({
            identifier: email,
            type: 'PASSWORD_RESET',
        });

        const user = await this.prisma.user.findUnique({
            where: { email },
        });

        if (!user) return { success: true };

        const rawToken = crypto.randomBytes(48).toString('hex');
        const tokenHash = this.hashToken(rawToken);

        await this.prisma.passwordReset.create({
            data: {
                userId: user.id,
                tokenHash,
                expiresAt: new Date(
                    Date.now() + RESET_TOKEN_TTL_HOURS * 3600000,
                ),
                ipAddress: params.ipAddress,
                userAgent: params.userAgent,
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
        if (params.newPassword.length < PASSWORD_MIN_LENGTH) {
            throw new BadRequestException('Password too weak');
        }

        const tokenHash = this.hashToken(params.token);

        const reset = await this.prisma.passwordReset.findFirst({
            where: {
                tokenHash,
                used: false,
                expiresAt: { gt: new Date() },
            },
        });

        if (!reset) {
            throw new BadRequestException('Invalid or expired token');
        }

        const passwordHash = await bcrypt.hash(params.newPassword, 12);

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
                data: {
                    used: true,
                    usedAt: new Date(),
                },
            }),
            this.prisma.session.updateMany({
                where: { userId: reset.userId },
                data: {
                    isActive: false,
                    invalidatedAt: new Date(),
                    invalidationReason: 'PASSWORD_RESET',
                },
            }),
        ]);

        await this.prisma.userAuditLog.create({
            data: {
                userId: reset.userId,
                eventType: 'SECURITY',
                eventAction: 'PASSWORD_RESET',
                ipAddress: params.ipAddress,
                userAgent: params.userAgent,
                success: true,
            },
        });

        return { success: true };
    }

    /* ------------------------------------------------------------------ */
    /* PASSWORD CHANGE (RECOMMENDED: REQUIRE MFA VIA CONTROLLER)           */
    /* ------------------------------------------------------------------ */

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

        const newHash = await bcrypt.hash(params.newPassword, 12);

        await this.prisma.$transaction([
            this.prisma.authAccount.update({
                where: { id: account.id },
                data: { passwordHash: newHash },
            }),
            this.prisma.session.updateMany({
                where: { userId: params.userId },
                data: {
                    isActive: false,
                    invalidatedAt: new Date(),
                    invalidationReason: 'PASSWORD_CHANGED',
                },
            }),
        ]);

        await this.prisma.userAuditLog.create({
            data: {
                userId: params.userId,
                eventType: 'SECURITY',
                eventAction: 'PASSWORD_CHANGED',
                ipAddress: params.ipAddress,
                userAgent: params.userAgent,
                success: true,
            },
        });

        return { success: true };
    }

    /* ------------------------------------------------------------------ */
    /* HELPERS                                                            */
    /* ------------------------------------------------------------------ */

    private async recordLoginFailure(
        identifier: string,
        params: { ipAddress: string; userAgent: string },
    ) {
        await this.abuse.recordFailedLogin({
            identifier,
            ipAddress: params.ipAddress,
            userAgent: params.userAgent,
        });
    }

    private hashToken(token: string): string {
        return crypto.createHash('sha256').update(token).digest('hex');
    }
}
