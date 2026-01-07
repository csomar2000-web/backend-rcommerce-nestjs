import {
  Body,
  Controller,
  Post,
  Get,
  Req,
  UseGuards,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { PasswordResetRequestDto } from './dto/password-reset.dto';
import { PasswordResetConfirmDto } from './dto/password-reset-confirm.dto';
import { PasswordChangeDto } from './dto/password-change.dto';
import { RevokeSessionDto } from './dto/revoke-session.dto';
import { GoogleAuthDto } from './dto/google-auth.dto';
import { FacebookAuthDto } from './dto/facebook-auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) { }

  @Post('register')
  register(@Body() dto: RegisterDto, @Req() req: Request) {
    return this.auth.register({
      ...dto,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  @Post('verify-email')
  verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.auth.verifyEmail(dto.token);
  }

  @Post('resend-verification')
  resendVerification(@Body() dto: ResendVerificationDto) {
    return this.auth.resendVerification(dto.email);
  }

  @Post('login')
  login(@Body() dto: LoginDto, @Req() req: Request) {
    return this.auth.login({
      ...dto,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  @Post('refresh')
  refresh(@Body() dto: RefreshTokenDto, @Req() req: Request) {
    return this.auth.refresh({
      refreshToken: dto.refreshToken,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  logout(@Req() req: any) {
    const accessToken = this.extractAccessToken(req);

    return this.auth.logout({
      userId: req.user.userId,
      sessionId: req.user.sessionId,
      accessToken,
    });
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  logoutAll(@Req() req: any) {
    const accessToken = this.extractAccessToken(req);

    return this.auth.logoutAll({
      userId: req.user.userId,
      accessToken,
    });
  }

  @Post('password-reset')
  requestPasswordReset(
    @Body() dto: PasswordResetRequestDto,
    @Req() req: Request,
  ) {
    return this.auth.requestPasswordReset({
      email: dto.email,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  @Post('password-reset/confirm')
  confirmPasswordReset(@Body() dto: PasswordResetConfirmDto) {
    return this.auth.confirmPasswordReset(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('password-change')
  changePassword(@Req() req: any, @Body() dto: PasswordChangeDto) {
    return this.auth.changePassword({
      userId: req.user.userId,
      ...dto,
    });
  }

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  listSessions(@Req() req: any) {
    return this.auth.listSessions(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('sessions/revoke')
  revokeSession(@Req() req: any, @Body() dto: RevokeSessionDto) {
    const accessToken = this.extractAccessToken(req);

    return this.auth.revokeSession({
      userId: req.user.userId,
      sessionId: dto.sessionId,
      accessToken,
    });
  }

  @Post('google')
  googleAuth(@Body() dto: GoogleAuthDto, @Req() req: Request) {
    return this.auth.loginWithGoogle({
      idToken: dto.idToken,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  @Post('facebook')
  facebookAuth(@Body() dto: FacebookAuthDto, @Req() req: Request) {
    return this.auth.loginWithFacebook({
      accessToken: dto.accessToken,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  private extractAccessToken(req: Request): string {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw new UnauthorizedException();
    }
    return header.slice(7);
  }
}
