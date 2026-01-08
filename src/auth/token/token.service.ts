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

    generateAccessToken(
        userId: string,
        role: string,
        sessionId: string,
    ): string {
        const jti = crypto.randomUUID();

        return this.jwt.sign(
            {
                sub: userId,
                role,
                sessionId,
                jti,
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
        reason: string,
    ): Promise<void> {
        const payload = this.decodeAccessToken(rawAccessToken);

        await this.prisma.tokenBlacklist.create({
            data: {
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

    async generateRefreshToken(params: {
        userId: string;
        sessionId: string;
        ipAddress: string;
        userAgent: string;
    }): Promise<{ refreshToken: string }> {
        const rawToken = crypto.randomBytes(64).toString('hex');
        const hashedToken = this.hash(rawToken);

        await this.prisma.refreshToken.create({
            data: {
                userId: params.userId,
                sessionId: params.sessionId,
                token: hashedToken,
                expiresAt: new Date(
                    Date.now() + this.parseTtl(
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

        const token = await this.prisma.refreshToken.findUnique({
            where: { token: hashedToken },
        });

        if (!token) {
            throw new ForbiddenException('Invalid refresh token');
        }

        const session = await this.prisma.session.findUnique({
            where: { id: token.sessionId },
        });

        if (!session || session.expiresAt <= new Date()) {
            throw new ForbiddenException('Session expired');
        }

        await this.prisma.refreshToken.delete({
            where: { id: token.id },
        });

        const { refreshToken } = await this.generateRefreshToken({
            userId: token.userId,
            sessionId: token.sessionId,
            ipAddress: params.ipAddress,
            userAgent: params.userAgent,
        });

        return {
            userId: token.userId,
            sessionId: token.sessionId,
            refreshToken,
        };
    }

    async invalidateSession(
        sessionId: string,
        reason: string,
    ): Promise<void> {
        await this.prisma.session.update({
            where: { id: sessionId },
            data: {
                revokedAt: new Date(),
            },
        });

        await this.prisma.refreshToken.deleteMany({
            where: { sessionId },
        });
    }

    async cleanupExpiredAuthData(): Promise<void> {
        const now = new Date();

        await this.prisma.refreshToken.deleteMany({
            where: { expiresAt: { lt: now } },
        });

        await this.prisma.session.deleteMany({
            where: { expiresAt: { lt: now } },
        });

        await this.prisma.tokenBlacklist.deleteMany({
            where: { expiresAt: { lt: now } },
        });
    }

    private hash(value: string): string {
        return crypto.createHash('sha256').update(value).digest('hex');
    }

    private parseTtl(ttl: string): number {
        const match = ttl.match(/^(\d+)([dhm])$/);
        if (!match) throw new Error(`Invalid TTL: ${ttl}`);

        const value = Number(match[1]);
        const unit = match[2];

        if (unit === 'd') return value * 86400000;
        if (unit === 'h') return value * 3600000;
        return value * 60000;
    }
}
