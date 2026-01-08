import {
    Injectable,
    ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import * as crypto from 'crypto';

interface DecodedAccessToken {
    sub: string;
    role: string;
    sessionId: string;
    jti: string;
    exp: number;
}

@Injectable()
export class TokenService {
    constructor(
        private readonly jwt: JwtService,
        private readonly config: ConfigService,
        private readonly prisma: PrismaService,
    ) { }

    /* ------------------------------------------------------------------
     * Access Tokens
     * ------------------------------------------------------------------ */

    generateAccessToken(
        userId: string,
        role: string,
        sessionId: string,
    ): string {
        return this.jwt.sign(
            {
                sub: userId,
                role,
                sessionId,
                jti: crypto.randomUUID(),
            },
            {
                issuer: 'auth-service',
                audience: 'api',
                expiresIn: this.config.getOrThrow('JWT_ACCESS_TTL'),
            },
        );
    }

    decodeAccessToken(token: string): DecodedAccessToken {
        return this.jwt.verify(token, {
            secret: this.config.getOrThrow('JWT_ACCESS_SECRET'),
            issuer: 'auth-service',
            audience: 'api',
        });
    }

    async blacklistAccessTokenFromJwt(
        rawAccessToken: string,
        _reason: string,
    ): Promise<void> {
        const payload = this.decodeAccessToken(rawAccessToken);

        await this.prisma.tokenBlacklist.upsert({
            where: { token: this.hash(payload.jti) },
            update: {},
            create: {
                token: this.hash(payload.jti),
                expiresAt: new Date(payload.exp * 1000),
            },
        });
    }

    async isAccessTokenBlacklisted(jti: string): Promise<boolean> {
        const record = await this.prisma.tokenBlacklist.findUnique({
            where: { token: this.hash(jti) },
        });

        return !!record && record.expiresAt > new Date();
    }

    /* ------------------------------------------------------------------
     * Refresh Tokens
     * ------------------------------------------------------------------ */

    async generateRefreshToken(params: {
        userId: string;
        sessionId: string;
        ipAddress: string;
        userAgent: string;
        familyId?: string;
    }): Promise<{ refreshToken: string }> {
        const rawToken = crypto.randomBytes(64).toString('hex');

        await this.prisma.refreshToken.create({
            data: {
                userId: params.userId,
                sessionId: params.sessionId,
                token: this.hash(rawToken),
                familyId: params.familyId ?? crypto.randomUUID(),
                expiresAt: new Date(
                    Date.now() +
                    this.parseTtl(
                        this.config.getOrThrow('JWT_REFRESH_TTL'),
                    ),
                ),
                ipAddress: params.ipAddress,
                userAgent: params.userAgent,
            },
        });

        return { refreshToken: rawToken };
    }

    async rotateRefreshToken(params: {
        refreshToken: string;
        ipAddress: string;
        userAgent: string;
    }): Promise<{
        userId: string;
        sessionId: string;
        refreshToken: string;
    }> {
        const hashedToken = this.hash(params.refreshToken);

        return this.prisma.$transaction(async (tx) => {
            const token = await tx.refreshToken.findUnique({
                where: { token: hashedToken },
            });

            if (!token) {
                throw new ForbiddenException('Invalid refresh token');
            }

            if (
                token.ipAddress !== params.ipAddress ||
                token.userAgent !== params.userAgent
            ) {
                await tx.refreshToken.deleteMany({
                    where: { familyId: token.familyId },
                });
                throw new ForbiddenException('Refresh token device mismatch');
            }

            const session = await tx.session.findUnique({
                where: { id: token.sessionId },
            });

            if (
                !session ||
                session.expiresAt <= new Date() ||
                session.revokedAt !== null
            ) {
                await tx.refreshToken.deleteMany({
                    where: { familyId: token.familyId },
                });
                throw new ForbiddenException('Session revoked');
            }

            await tx.refreshToken.deleteMany({
                where: { familyId: token.familyId },
            });

            const { refreshToken } = await this.generateRefreshToken({
                userId: token.userId,
                sessionId: token.sessionId,
                ipAddress: params.ipAddress,
                userAgent: params.userAgent,
                familyId: token.familyId,
            });

            return {
                userId: token.userId,
                sessionId: token.sessionId,
                refreshToken,
            };
        });
    }

    /* ------------------------------------------------------------------
     * Session Invalidation
     * ------------------------------------------------------------------ */

    async invalidateSession(
        sessionId: string,
        _reason: string,
    ): Promise<void> {
        await this.prisma.$transaction([
            this.prisma.session.update({
                where: { id: sessionId },
                data: { revokedAt: new Date() },
            }),
            this.prisma.refreshToken.deleteMany({
                where: { sessionId },
            }),
        ]);
    }

    async invalidateAllUserSessions(
        userId: string,
        _reason: string,
    ): Promise<void> {
        await this.prisma.$transaction([
            this.prisma.session.updateMany({
                where: {
                    userId,
                    revokedAt: null,
                },
                data: { revokedAt: new Date() },
            }),
            this.prisma.refreshToken.deleteMany({
                where: { userId },
            }),
        ]);
    }

    /* ------------------------------------------------------------------
     * Cleanup
     * ------------------------------------------------------------------ */

    async cleanupExpiredAuthData(): Promise<void> {
        const now = new Date();

        await this.prisma.$transaction([
            this.prisma.refreshToken.deleteMany({
                where: { expiresAt: { lt: now } },
            }),
            this.prisma.session.deleteMany({
                where: { expiresAt: { lt: now } },
            }),
            this.prisma.tokenBlacklist.deleteMany({
                where: { expiresAt: { lt: now } },
            }),
        ]);
    }

    /* ------------------------------------------------------------------
     * Helpers
     * ------------------------------------------------------------------ */

    private hash(value: string): string {
        return crypto.createHash('sha256').update(value).digest('hex');
    }

    private parseTtl(ttl: string): number {
        const match = ttl.match(/^(\d+)([dhm])$/);
        if (!match) throw new Error(`Invalid TTL: ${ttl}`);

        const value = Number(match[1]);
        const unit = match[2];

        switch (unit) {
            case 'd':
                return value * 86_400_000;
            case 'h':
                return value * 3_600_000;
            case 'm':
                return value * 60_000;
            default:
                throw new Error(`Invalid TTL unit: ${unit}`);
        }
    }
}
