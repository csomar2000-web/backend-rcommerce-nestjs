import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';

import { AccountIdentityService } from './services/account-identity.service';
import { CredentialsPasswordsService } from './services/credentials-passwords.service';
import { SessionsDevicesService } from './services/sessions-devices.service';
import { TokensOrchestrationService } from './services/tokens-orchestration.service';
import { AuthorizationService } from './services/authorization.service';
import { SecurityAbuseService } from './services/security-abuse.service';
import { AuditObservabilityService } from './services/audit-observability.service';

import { GoogleAuthService } from './services/google-auth.service';
import { FacebookAuthService } from './services/facebook-auth.service';

import { AuthProvider } from '@prisma/client';
import { SocialProfile } from './types/social-profile.type';

@Injectable()
export class AuthService {
  constructor(
    private readonly accountIdentity: AccountIdentityService,
    private readonly credentials: CredentialsPasswordsService,
    private readonly sessions: SessionsDevicesService,
    private readonly tokens: TokensOrchestrationService,
    private readonly authorization: AuthorizationService,
    private readonly security: SecurityAbuseService,
    private readonly audit: AuditObservabilityService,
    private readonly googleAuth: GoogleAuthService,
    private readonly facebookAuth: FacebookAuthService,
  ) { }

  /* --------------------------------------------------------------------------
   * Registration & email verification
   * -------------------------------------------------------------------------- */

  register(dto: any) {
    return this.accountIdentity.register(dto);
  }

  verifyEmail(token: string) {
    return this.accountIdentity.verifyEmail(token);
  }

  resendVerification(email: string) {
    this.security.assertSensitiveActionAllowed({
      identifier: email,
      type: 'EMAIL_VERIFICATION',
    });

    return this.accountIdentity.resendVerification(email);
  }

  /* --------------------------------------------------------------------------
   * Local authentication
   * -------------------------------------------------------------------------- */

  async login(dto: any) {
    await this.security.assertLoginAllowed({
      identifier: dto.email,
    });

    try {
      const result = await this.credentials.login(dto);
      await this.security.clearLoginFailures(dto.email);
      return result;
    } catch (error) {
      await this.security.recordFailedLogin({
        identifier: dto.email,
        ipAddress: dto.ipAddress,
        userAgent: dto.userAgent,
      });
      throw error;
    }
  }

  refresh(dto: any) {
    return this.tokens.refreshTokens(dto);
  }

  logout(dto: { userId: string; sessionId: string; accessToken: string }) {
    return this.sessions.logoutCurrentSession(dto);
  }

  logoutAll(dto: { userId: string; accessToken: string }) {
    return this.sessions.logoutAllSessions(dto);
  }

  /* --------------------------------------------------------------------------
   * Password management
   * -------------------------------------------------------------------------- */

  requestPasswordReset(dto: any) {
    return this.credentials.requestPasswordReset(dto);
  }

  confirmPasswordReset(dto: any) {
    return this.credentials.confirmPasswordReset(dto);
  }

  changePassword(dto: any) {
    return this.credentials.changePassword(dto);
  }

  /* --------------------------------------------------------------------------
   * Sessions
   * -------------------------------------------------------------------------- */

  listSessions(userId: string) {
    return this.sessions.listSessions(userId);
  }

  revokeSession(dto: {
    userId: string;
    sessionId: string;
    accessToken: string;
  }) {
    return this.sessions.revokeSession(dto);
  }

  /* --------------------------------------------------------------------------
   * Social authentication
   * -------------------------------------------------------------------------- */

  async loginWithGoogle(dto: {
    idToken: string;
    ipAddress: string;
    userAgent: string;
  }) {
    await this.security.assertLoginAllowed({
      identifier: 'google',
    });

    const profile = await this.googleAuth.verifyIdToken(dto.idToken);

    return this.handleSocialLogin(AuthProvider.GOOGLE, profile, dto);
  }

  async loginWithFacebook(dto: {
    accessToken: string;
    ipAddress: string;
    userAgent: string;
  }) {
    await this.security.assertLoginAllowed({
      identifier: 'facebook',
    });

    const profile = await this.facebookAuth.verifyAccessToken(dto.accessToken);

    return this.handleSocialLogin(AuthProvider.FACEBOOK, profile, dto);
  }

  /* --------------------------------------------------------------------------
   * Core social login orchestration
   * -------------------------------------------------------------------------- */

  private async handleSocialLogin(
    provider: AuthProvider,
    profile: SocialProfile,
    context: { ipAddress: string; userAgent: string },
  ) {
    if (!profile.email) {
      throw new UnauthorizedException('Social account has no email');
    }

    if (!profile.emailVerified) {
      throw new UnauthorizedException('Email is not verified');
    }

    const { user, authAccount } =
      await this.accountIdentity.upsertSocialAccount({
        provider,
        providerId: profile.providerId,
        email: profile.email,
        emailVerified: profile.emailVerified,
        name: profile.name,
        avatarUrl: profile.avatar,
      });

    const session = await this.sessions.createSession({
      userId: user.id,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });

    await this.audit.audit({
      userId: user.id,
      eventType: 'AUTH',
      eventAction: 'SOCIAL_LOGIN',
      success: true,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      metadata: {
        provider,
        authAccountId: authAccount.id,
      },
    });



    return this.tokens.issueTokens({
      userId: user.id,
      sessionId: session.id,
      role: 'CUSTOMER',
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });

  }
}
