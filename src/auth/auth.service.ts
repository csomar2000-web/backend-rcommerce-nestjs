import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { randomUUID } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { TokenService } from './token/token.service';

export type AuthRequestMetadata = {
  ipAddress?: string;
  userAgent?: string;
};

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
  ) {}

  /**
   * REGISTER (email + password)
   */
  async register(email: string, password: string, metadata: AuthRequestMetadata) {
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

    return this.issueTokens(user.id, user.role, metadata);
  }

  /**
   * LOGIN (email + password)
   */
  async login(email: string, password: string, metadata: AuthRequestMetadata) {
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

    const passwordValid = await bcrypt.compare(password, account.passwordHash);

    if (!passwordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    await this.prisma.authAccount.update({
      where: { id: account.id },
      data: { lastUsedAt: new Date() },
    });

    return this.issueTokens(account.user.id, account.user.role, metadata);
  }

  /**
   * REFRESH TOKENS
   */
  async refresh(refreshToken: string, metadata: AuthRequestMetadata) {
    const payload = this.tokenService.verifyRefreshToken(refreshToken);
    const tokenHash = this.tokenService.hashToken(refreshToken);

    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { session: true, user: true },
    });

    if (!storedToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (storedToken.isRevoked) {
      await this.revokeTokenFamily(storedToken.tokenFamily, 'Reuse detected');
      throw new UnauthorizedException('Refresh token revoked');
    }

    if (storedToken.expiresAt < new Date()) {
      await this.revokeTokenFamily(storedToken.tokenFamily, 'Token expired');
      throw new UnauthorizedException('Refresh token expired');
    }

    if (!storedToken.session.isActive) {
      throw new UnauthorizedException('Session inactive');
    }

    if (
      payload.sub !== storedToken.userId ||
      payload.sessionId !== storedToken.sessionId ||
      payload.tokenFamily !== storedToken.tokenFamily
    ) {
      throw new UnauthorizedException('Refresh token mismatch');
    }

    const newRefreshToken = this.tokenService.generateRefreshToken({
      sub: storedToken.userId,
      sessionId: storedToken.sessionId,
      tokenFamily: storedToken.tokenFamily,
    });
    const newRefreshHash = this.tokenService.hashToken(newRefreshToken);
    const expiresAt = this.tokenService.getRefreshTokenExpiresAt();

    await this.prisma.$transaction([
      this.prisma.refreshToken.update({
        where: { id: storedToken.id },
        data: {
          isRevoked: true,
          revokedAt: new Date(),
          replacedByHash: newRefreshHash,
        },
      }),
      this.prisma.refreshToken.create({
        data: {
          userId: storedToken.userId,
          sessionId: storedToken.sessionId,
          tokenHash: newRefreshHash,
          tokenFamily: storedToken.tokenFamily,
          expiresAt,
          ipAddress: metadata.ipAddress ?? storedToken.ipAddress,
          userAgent: metadata.userAgent ?? storedToken.userAgent,
        },
      }),
      this.prisma.session.update({
        where: { id: storedToken.sessionId },
        data: {
          lastActivityAt: new Date(),
          expiresAt,
        },
      }),
    ]);

    return {
      accessToken: this.tokenService.generateAccessToken(
        storedToken.userId,
        storedToken.user.role,
      ),
      refreshToken: newRefreshToken,
    };
  }

  /**
   * LOGOUT (revoke refresh token + session)
   */
  async logout(refreshToken: string) {
    const payload = this.tokenService.verifyRefreshToken(refreshToken);
    const tokenHash = this.tokenService.hashToken(refreshToken);

    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { session: true },
    });

    if (!storedToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (
      payload.sub !== storedToken.userId ||
      payload.sessionId !== storedToken.sessionId ||
      payload.tokenFamily !== storedToken.tokenFamily
    ) {
      throw new UnauthorizedException('Refresh token mismatch');
    }

    await this.revokeTokenFamily(storedToken.tokenFamily, 'User logout');
  }

  /**
   * INTERNAL TOKEN ISSUER
   */
  private async issueTokens(
    userId: string,
    role: string,
    metadata: AuthRequestMetadata,
  ) {
    const session = await this.prisma.session.create({
      data: {
        userId,
        ipAddress: metadata.ipAddress ?? 'unknown',
        userAgent: metadata.userAgent ?? 'unknown',
        expiresAt: this.tokenService.getRefreshTokenExpiresAt(),
      },
    });

    const tokenFamily = randomUUID();
    const refreshToken = this.tokenService.generateRefreshToken({
      sub: userId,
      sessionId: session.id,
      tokenFamily,
    });
    const refreshHash = this.tokenService.hashToken(refreshToken);

    await this.prisma.refreshToken.create({
      data: {
        userId,
        sessionId: session.id,
        tokenHash: refreshHash,
        tokenFamily,
        expiresAt: session.expiresAt,
        ipAddress: metadata.ipAddress ?? 'unknown',
        userAgent: metadata.userAgent ?? 'unknown',
      },
    });

    return {
      accessToken: this.tokenService.generateAccessToken(userId, role),
      refreshToken,
    };
  }

  private async revokeTokenFamily(tokenFamily: string, reason: string) {
    const revokedAt = new Date();
    await this.prisma.$transaction([
      this.prisma.refreshToken.updateMany({
        where: { tokenFamily, isRevoked: false },
        data: { isRevoked: true, revokedAt },
      }),
      this.prisma.session.updateMany({
        where: { refreshTokens: { some: { tokenFamily } } },
        data: {
          isActive: false,
          invalidatedAt: revokedAt,
          invalidationReason: reason,
        },
      }),
    ]);
  }
}
