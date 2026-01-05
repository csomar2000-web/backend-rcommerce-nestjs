// src/config/jwt.config.ts
import { StringValue } from 'ms';

if (!process.env.JWT_ACCESS_SECRET || !process.env.JWT_REFRESH_SECRET) {
  throw new Error('JWT secrets are not defined');
}

export const jwtConfig = {
  accessTokenSecret: process.env.JWT_ACCESS_SECRET,
  refreshTokenSecret: process.env.JWT_REFRESH_SECRET,
  accessTokenTtl: '15m' as StringValue,
  refreshTokenTtl: '7d' as StringValue,
};
