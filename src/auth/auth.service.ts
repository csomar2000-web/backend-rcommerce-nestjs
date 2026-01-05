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
  ) {}

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
      this.tokenService.generateAccessToken(user.id, 'CUSTOMER');

    const { refreshToken } =
      await this.tokenService.generateRefreshToken({
        userId: user.id,
        sessionId: session.id,
        ipAddress,
        userAgent,
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
      );

    const { refreshToken } =
      await this.tokenService.generateRefreshToken({
        userId: account.user.id,
        sessionId: session.id,
        ipAddress,
        userAgent,
      });

    return { accessToken, refreshToken };
  }
}
