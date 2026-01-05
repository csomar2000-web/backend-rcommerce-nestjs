import {
    Injectable,
    UnauthorizedException,
    ConflictException,
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

    /**
     * REGISTER (email + password)
     */
    async register(email: string, password: string) {
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
                role: 'CUSTOMER',
                accountStatus: 'ACTIVE',
                authAccounts: {
                    create: {
                        provider: 'LOCAL',
                        email,
                        passwordHash,
                    },
                },
            },
        });

        return this.issueTokens(user.id, user.role);
    }

    /**
     * LOGIN (email + password)
     */
    async login(email: string, password: string) {
        const account = await this.prisma.authAccount.findFirst({
            where: {
                provider: 'LOCAL',
                email,
            },
            include: {
                user: true,
            },
        });

        if (!account || !account.passwordHash) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const passwordValid = await bcrypt.compare(
            password,
            account.passwordHash,
        );

        if (!passwordValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        return this.issueTokens(account.user.id, account.user.role);
    }

    /**
     * INTERNAL TOKEN ISSUER
     */
    private issueTokens(userId: string, role: string) {
        return {
            accessToken: this.tokenService.generateAccessToken(userId, role),
            refreshToken: this.tokenService.generateRefreshToken(userId),
        };
    }
}
