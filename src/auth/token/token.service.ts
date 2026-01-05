import {
    Injectable,
    ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import * as crypto from 'crypto';

@Injectable()
export class TokenService {
    constructor(
        private readonly jwt: JwtService,
        private readonly config: ConfigService,
        private readonly prisma: PrismaService,
    ) { }


    generateAccessToken(userId: string, role: string): string {
        return this.jwt.sign({
            sub: userId,
            role,
        });
    }

    async generateRefreshToken(params: {
        userId: string;
        sessionId: string;
        ipAddress: string;
        userAgent: string;
        tokenFamily?: string;
    }): Promise<{ refreshToken: string }> {
        const {
            userId,
            sessionId,
            ipAddress,
            userAgent,
            tokenFamily = crypto.randomUUID(),
        } = params;

        const rawToken = crypto.randomBytes(64).toString('hex');
        const tokenHash = this.hashToken(rawToken);

        const expiresAt = new Date(
            Date.now() +
            this.parseTtl(
                this.config.getOrThrow<string>('JWT_REFRESH_TTL'),
            ),
        );


        await this.prisma.refreshToken.create({
            data: {
                userId,
                sessionId,
                tokenHash,
                tokenFamily,
                expiresAt,
                ipAddress,
                userAgent,
            },
        });

        return { refreshToken: rawToken };
    }


    async rotateRefreshToken(params: {
        refreshToken: string;
        ipAddress: string;
        userAgent: string;
    }) {
        const tokenHash = this.hashToken(params.refreshToken);

        const existingToken =
            await this.prisma.refreshToken.findUnique({
                where: { tokenHash },
                include: { session: true },
            });

        if (!existingToken) {
            throw new ForbiddenException('Invalid refresh token');
        }

        if (existingToken.isRevoked) {
            await this.invalidateSession(
                existingToken.sessionId,
                'TOKEN_REUSE_DETECTED',
            );

            throw new ForbiddenException(
                'Refresh token reuse detected',
            );
        }

        if (existingToken.expiresAt < new Date()) {
            throw new ForbiddenException('Refresh token expired');
        }

        await this.prisma.refreshToken.update({
            where: { id: existingToken.id },
            data: {
                isRevoked: true,
                revokedAt: new Date(),
            },
        });

        return this.generateRefreshToken({
            userId: existingToken.userId,
            sessionId: existingToken.sessionId,
            tokenFamily: existingToken.tokenFamily,
            ipAddress: params.ipAddress,
            userAgent: params.userAgent,
        });
    }
    async invalidateSession(
        sessionId: string,
        reason: string,
    ) {
        await this.prisma.session.update({
            where: { id: sessionId },
            data: {
                isActive: false,
                invalidatedAt: new Date(),
                invalidationReason: reason,
            },
        });

        await this.prisma.refreshToken.updateMany({
            where: { sessionId },
            data: {
                isRevoked: true,
                revokedAt: new Date(),
            },
        });
    }


    private hashToken(token: string): string {
        return crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');
    }

    private parseTtl(ttl: string): number {
        const value = parseInt(ttl, 10);
        if (ttl.endsWith('d')) return value * 86400000;
        if (ttl.endsWith('h')) return value * 3600000;
        if (ttl.endsWith('m')) return value * 60000;
        return value * 1000;
    }
}
