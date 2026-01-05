import {
  Body,
  Controller,
  Post,
  Req,
  UseGuards,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import {
  Throttle,
  ThrottlerGuard,
} from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

interface AuthenticatedRequest extends Request {
  user: {
    userId: string;
    role: string;
    sessionId: string;
  };
}

@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Throttle({ limit: 3, ttl: 60 })
  @Post('register')
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
  ) {
    return this.authService.register({
      email: dto.email,
      password: dto.password,
      confirmPassword: dto.confirmPassword,
      phoneNumber: dto.phoneNumber,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  @Throttle({ limit: 5, ttl: 60 })
  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
  ) {
    return this.authService.login({
      email: dto.email,
      password: dto.password,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  @Throttle({ limit: 10, ttl: 60 })
  @Post('refresh')
  async refresh(
    @Body() dto: RefreshTokenDto,
    @Req() req: Request,
  ) {
    if (!dto.refreshToken || dto.refreshToken.length < 64) {
      throw new UnauthorizedException();
    }

    return this.authService.refresh({
      refreshToken: dto.refreshToken,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Req() req: AuthenticatedRequest) {
    return this.authService.logout({
      userId: req.user.userId,
      sessionId: req.user.sessionId,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  async logoutAll(@Req() req: AuthenticatedRequest) {
    return this.authService.logoutAll({
      userId: req.user.userId,
    });
  }
}
