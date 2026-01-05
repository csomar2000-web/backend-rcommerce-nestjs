// src/auth/token/token.service.ts
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { jwtConfig } from '../../config/jwt.config';
import { createHash } from 'crypto';

export type RefreshTokenPayload = {
  sub: string;
  sessionId: string;
  tokenFamily: string;
};

@Injectable()
export class TokenService {
  constructor(private readonly jwt: JwtService) {}

  generateAccessToken(userId: string, role: string): string {
    return this.jwt.sign({
      sub: userId,
      role,
    });
  }

  generateRefreshToken(payload: RefreshTokenPayload): string {
    return this.jwt.sign(payload, {
      secret: jwtConfig.refreshTokenSecret,
      expiresIn: jwtConfig.refreshTokenTtl,
    });
  }

  verifyRefreshToken(token: string): RefreshTokenPayload {
    return this.jwt.verify<RefreshTokenPayload>(token, {
      secret: jwtConfig.refreshTokenSecret,
    });
  }

  hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  getRefreshTokenExpiresAt(): Date {
    const ttlMs = this.parseDuration(jwtConfig.refreshTokenTtl);
    return new Date(Date.now() + ttlMs);
  }

  private parseDuration(value: string): number {
    const match = value.trim().match(/^(\d+)([smhd])$/i);
    if (!match) {
      throw new Error(`Unsupported duration format: ${value}`);
    }

    const amount = Number(match[1]);
    const unit = match[2].toLowerCase();

    switch (unit) {
      case 's':
        return amount * 1000;
      case 'm':
        return amount * 60 * 1000;
      case 'h':
        return amount * 60 * 60 * 1000;
      case 'd':
        return amount * 24 * 60 * 60 * 1000;
      default:
        throw new Error(`Unsupported duration unit: ${unit}`);
    }
  }
}
