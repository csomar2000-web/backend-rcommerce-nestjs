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
import { AccountIdentityService } from './services/account-identity.service';

import { RegisterDto } from './dto/auth/register.dto';
import { LoginDto } from './dto/auth/login.dto';
import { RefreshTokenDto } from './dto/auth/refresh-token.dto';

import { VerifyEmailDto } from './dto/email/verify-email.dto';
import { ResendVerificationDto } from './dto/email/resend-verification.dto';

import {
  ForgotPasswordDto,
  ResetPasswordDto,
  ChangePasswordDto,
} from './dto/password';

import { RevokeSessionDto } from './dto/session/revoke-session.dto';

import { GoogleAuthDto } from './dto/oauth/google-auth.dto';
import { FacebookAuthDto } from './dto/oauth/facebook-auth.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly accountIdentity: AccountIdentityService,
  ) { }

  /* ----------------------------- Registration ----------------------------- */

  @Post('register')
  register(@Body() dto: RegisterDto, @Req() req: Request) {
    return this.auth.register({
      email: dto.email,
      password: dto.password,
      phoneNumber: dto.phoneNumber,
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

  /* --------------------------------- Login -------------------------------- */

  @Post('login')
  login(@Body() dto: LoginDto, @Req() req: Request) {
    return this.auth.login({
      email: dto.email,
      password: dto.password,
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

  /* ------------------------------- Logout --------------------------------- */

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  logout(@Req() req: any) {
    return this.auth.logout({
      userId: req.user.userId,
      sessionId: req.user.sessionId,
      accessToken: this.extractAccessToken(req),
    });
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  logoutAll(@Req() req: any) {
    return this.auth.logoutAll({
      userId: req.user.userId,
      accessToken: this.extractAccessToken(req),
    });
  }

  /* -------------------------- Password Reset ------------------------------- */

  @Post('password-reset')
  requestPasswordReset(
    @Body() dto: ForgotPasswordDto,
    @Req() req: Request,
  ) {
    return this.auth.requestPasswordReset({
      email: dto.email,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  @Post('password-reset/confirm')
  confirmPasswordReset(
    @Body() dto: ResetPasswordDto,
    @Req() req: Request,
  ) {
    return this.auth.confirmPasswordReset({
      token: dto.token,
      newPassword: dto.newPassword,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  /* -------------------------- Password Change ------------------------------ */

  @UseGuards(JwtAuthGuard)
  @Post('password-change')
  changePassword(@Req() req: any, @Body() dto: ChangePasswordDto) {
    return this.auth.changePassword({
      userId: req.user.userId,
      currentPassword: dto.currentPassword,
      newPassword: dto.newPassword,
      ipAddress: req.ip ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    });
  }

  /* ------------------------------ Sessions -------------------------------- */

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  listSessions(@Req() req: any) {
    return this.auth.listSessions(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('sessions/revoke')
  revokeSession(@Req() req: any, @Body() dto: RevokeSessionDto) {
    return this.auth.revokeSession({
      userId: req.user.userId,
      sessionId: dto.sessionId,
      accessToken: this.extractAccessToken(req),
    });
  }

  /* ------------------------------ OAuth ----------------------------------- */

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

  /* -------------------------------- MFA ----------------------------------- */

  @UseGuards(JwtAuthGuard)
  @Post('mfa/setup')
  setupMfa(@Req() req: any) {
    return this.accountIdentity.setupMfaTotp(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('mfa/confirm')
  confirmMfa(@Req() req: any, @Body() dto: { code: string }) {
    return this.accountIdentity.confirmMfaTotp({
      userId: req.user.userId,
      code: dto.code,
    });
  }

  @Post('mfa/complete')
  completeMfa(
    @Body()
    dto: {
      userId: string;
      sessionId: string;
      mfaCode: string;
      ipAddress: string;
      userAgent: string;
    },
  ) {
    return this.auth.completeMfa(dto);
  }

  /* ------------------------------ Helpers --------------------------------- */

  private extractAccessToken(req: Request): string {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw new UnauthorizedException();
    }
    return header.slice(7);
  }
}
