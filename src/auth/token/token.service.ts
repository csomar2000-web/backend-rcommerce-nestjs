// src/auth/token/token.service.ts
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { jwtConfig } from '../../config/jwt.config';

@Injectable()
export class TokenService {
  constructor(private readonly jwt: JwtService) {}

  generateAccessToken(userId: string, role: string): string {
    return this.jwt.sign({
      sub: userId,
      role,
    });
  }

  generateRefreshToken(userId: string): string {
    return this.jwt.sign(
      { sub: userId },
      {
        secret: jwtConfig.refreshTokenSecret,
        expiresIn: jwtConfig.refreshTokenTtl,
      },
    );
  }
}
