import { Injectable, UnauthorizedException } from '@nestjs/common';
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

  async login(dto: {
    email: string;
    password: string;
    ipAddress: string;
    userAgent: string;
  }) {
    await this.security.assertLoginAllowed({
      identifier: dto.email,
    });

    try {
      const result = await this.credentials.login(dto);
      await this.security.clearLoginFailures(dto.email);

      if ('mfaRequired' in result) {
        return result;
      }

      return this.tokens.issueTokens({
        userId: result.userId,
        sessionId: result.sessionId,
        role: 'CUSTOMER',
        ipAddress: dto.ipAddress,
        userAgent: dto.userAgent,
      });
    } catch (error) {
      await this.security.recordFailedLogin({
        identifier: dto.email,
        ipAddress: dto.ipAddress,
        userAgent: dto.userAgent,
      });
      throw error;
    }
  }

  async completeMfa(dto: {
    userId: string;
    sessionId: string;
    mfaCode: string;
    ipAddress: string;
    userAgent: string;
  }) {
    await this.credentials.verifyMfaCode({
      userId: dto.userId,
      sessionId: dto.sessionId,
      code: dto.mfaCode,
    });

    return this.tokens.issueTokens({
      userId: dto.userId,
      sessionId: dto.sessionId,
      role: 'CUSTOMER',
      ipAddress: dto.ipAddress,
      userAgent: dto.userAgent,
    });
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

  requestPasswordReset(dto: any) {
    return this.credentials.requestPasswordReset(dto);
  }
  confirmPasswordReset(dto: {
    token: string;
    newPassword: string;
    ipAddress: string;
    userAgent: string;
  }) {
    return this.credentials.confirmPasswordReset(dto);
  }


  changePassword(dto: any) {
    return this.credentials.changePassword(dto);
  }

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

    const profile =
      await this.facebookAuth.verifyAccessToken(dto.accessToken);

    return this.handleSocialLogin(AuthProvider.FACEBOOK, profile, dto);
  }

  private async handleSocialLogin(
    provider: AuthProvider,
    profile: SocialProfile,
    context: { ipAddress: string; userAgent: string },
  ) {
    if (!profile.email || !profile.emailVerified) {
      throw new UnauthorizedException();
    }

    const { user, authAccount } =
      await this.accountIdentity.upsertSocialAccount({
        provider,
        providerId: profile.providerId,
        email: profile.email,
        emailVerified: profile.emailVerified,
      });

    const session = await this.sessions.createSession({
      userId: user.id,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });

    await this.audit.audit({
      userId: user.id,
      action: 'SOCIAL_LOGIN',
      success: true,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      resource: 'AUTH_ACCOUNT',
      resourceId: authAccount.id,
      metadata: { provider },
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
