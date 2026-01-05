import {
    Injectable,
    UnauthorizedException,
    ConflictException,
    BadRequestException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { TokenService } from './token/token.service';

@Injectable()
export class AuthService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly tokenService: TokenService,
    ) { }

    async register(params: {
        email: string;
        password: string;
        confirmPassword: string;
        phoneNumber: string;
        ipAddress: string;
        userAgent: string;
    }) {
        const {
            email,
            password,
            confirmPassword,
            phoneNumber,
            ipAddress,
            userAgent,
        } = params;

        if (password !== confirmPassword) {
            throw new BadRequestException('Passwords do not match');
        }

        if (
            !/(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}/.test(
                password,
            )
        ) {
            throw new BadRequestException('Weak password');
        }

        const existingUser = await this.prisma.user.findUnique({
            where: { email },
        });

        if (existingUser) {
            throw new ConflictException('Email already in use');
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const user = await this.prisma.user.create({
            data: {
                email,
                authAccounts: {
                    create: {
                        provider: 'LOCAL',
                        passwordHash,
                        isPrimary: true,
                        isVerified: false,
                    },
                },
                customerProfile: {
                    create: {
                        phoneNumber,
                    },
                },
            },
        });

        const session = await this.prisma.session.create({
            data: {
                userId: user.id,
                ipAddress,
                userAgent,
                expiresAt: new Date(
                    Date.now() + 1000 * 60 * 60 * 24 * 30,
                ),
            },
        });

        const accessToken =
            this.tokenService.generateAccessToken(
                user.id,
                'CUSTOMER',
                session.id,
            );

        const { refreshToken } =
            await this.tokenService.generateRefreshToken({
                userId: user.id,
                sessionId: session.id,
                ipAddress,
                userAgent,
            });

        await this.prisma.userAuditLog.create({
            data: {
                userId: user.id,
                eventType: 'AUTH',
                eventAction: 'REGISTER',
                ipAddress,
                userAgent,
                success: true,
            },
        });

        return { accessToken, refreshToken };
    }

    async login(params: {
        email: string;
        password: string;
        ipAddress: string;
        userAgent: string;
    }) {
        const { email, password, ipAddress, userAgent } = params;

        const account = await this.prisma.authAccount.findFirst({
            where: {
                provider: 'LOCAL',
                user: { email },
            },
            include: { user: true },
        });

        if (!account || !account.passwordHash) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const passwordValid = await bcrypt.compare(
            password,
            account.passwordHash,
        );

        if (!passwordValid) {
            await this.prisma.securityEvent.create({
                data: {
                    email,
                    eventType: 'FAILED_LOGIN',
                    severity: 'MEDIUM',
                    description: 'Invalid password',
                    ipAddress,
                    userAgent,
                },
            });
            throw new UnauthorizedException('Invalid credentials');
        }

        const session = await this.prisma.session.create({
            data: {
                userId: account.user.id,
                ipAddress,
                userAgent,
                expiresAt: new Date(
                    Date.now() + 1000 * 60 * 60 * 24 * 30,
                ),
            },
        });

        const accessToken =
            this.tokenService.generateAccessToken(
                account.user.id,
                'CUSTOMER',
                session.id,
            );

        const { refreshToken } =
            await this.tokenService.generateRefreshToken({
                userId: account.user.id,
                sessionId: session.id,
                ipAddress,
                userAgent,
            });

        await this.prisma.userAuditLog.create({
            data: {
                userId: account.user.id,
                eventType: 'AUTH',
                eventAction: 'LOGIN',
                ipAddress,
                userAgent,
                success: true,
            },
        });

        return { accessToken, refreshToken };
    }

    async refresh(params: {
        refreshToken: string;
        ipAddress: string;
        userAgent: string;
    }) {
        const {
            userId,
            sessionId,
            refreshToken: newRefreshToken,
        } = await this.tokenService.rotateRefreshToken({
            refreshToken: params.refreshToken,
            ipAddress: params.ipAddress,
            userAgent: params.userAgent,
        });

        const session = await this.prisma.session.findFirst({
            where: {
                id: sessionId,
                isActive: true,
            },
        });

        if (!session || session.expiresAt < new Date()) {
            throw new UnauthorizedException('Session invalid');
        }

        const accessToken =
            this.tokenService.generateAccessToken(
                userId,
                'CUSTOMER',
                sessionId,
            );

        await this.prisma.userAuditLog.create({
            data: {
                userId,
                eventType: 'AUTH',
                eventAction: 'REFRESH',
                ipAddress: params.ipAddress,
                userAgent: params.userAgent,
                success: true,
            },
        });

        return {
            accessToken,
            refreshToken: newRefreshToken,
        };
    }

    async logout(params: {
        userId: string;
        sessionId: string;
        ipAddress?: string;
        userAgent?: string;
    }) {
        await this.tokenService.invalidateSession(
            params.sessionId,
            'USER_LOGOUT',
        );

        await this.prisma.userAuditLog.create({
            data: {
                userId: params.userId,
                eventType: 'AUTH',
                eventAction: 'LOGOUT',
                ipAddress: params.ipAddress ?? 'unknown',
                userAgent: params.userAgent ?? 'unknown',
                success: true,
            },
        });

        return { success: true };
    }

    async logoutAll(params: {
        userId: string;
    }) {
        const sessions = await this.prisma.session.findMany({
            where: {
                userId: params.userId,
                isActive: true,
            },
            select: { id: true },
        });

        for (const session of sessions) {
            await this.tokenService.invalidateSession(
                session.id,
                'USER_LOGOUT_ALL',
            );
        }

        return { success: true };
    }

    
}
