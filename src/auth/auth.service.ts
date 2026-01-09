import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthProvider } from '@prisma/client';

import { AccountIdentityService } from './services/account-identity.service';
import { CredentialsPasswordsService } from './services/credentials-passwords.service';
import { SessionsDevicesService } from './services/sessions-devices.service';
import { TokensOrchestrationService } from './services/tokens-orchestration.service';
import { SecurityAbuseService } from './services/security-abuse.service';
import { AuditObservabilityService } from './services/audit-observability.service';
import { GoogleAuthService } from './services/google-auth.service';
import { FacebookAuthService } from './services/facebook-auth.service';

import {
  RegisterRequest,
  LoginRequest,
  RefreshRequest,
  PasswordResetRequest,
  ConfirmPasswordResetRequest,
  ChangePasswordRequest,
} from './types/auth-requests.type';

import { SocialProfile } from './types/social-profile.type';

@Injectable()
export class AuthService {
  constructor(
    private readonly accountIdentity: AccountIdentityService,
    private readonly credentials: CredentialsPasswordsService,
    private readonly sessions: SessionsDevicesService,
    private readonly tokens: TokensOrchestrationService,
    private readonly security: SecurityAbuseService,
    private readonly audit: AuditObservabilityService,
    private readonly googleAuth: GoogleAuthService,
    private readonly facebookAuth: FacebookAuthService,
  ) { }

  register(request: RegisterRequest) {
    return this.accountIdentity.register({
      email: request.email,
      password: request.password,
      confirmPassword: request.password,
      phone: request.phoneNumber,
      ipAddress: request.ipAddress,
      userAgent: request.userAgent,
    });
  }

  verifyEmail(token: string) {
    return this.accountIdentity.verifyEmail(token);
  }

  resendVerification(email: string) {
    return this.accountIdentity.resendVerification(email);
  }

  async login(request: LoginRequest) {
    const email = request.email.toLowerCase().trim();

    await this.security.assertLoginAllowed({
      email,
      ipAddress: request.ipAddress,
    });

    const result = await this.credentials.login(request);

    await this.security.clearLoginFailures(
      email,
      request.ipAddress,
    );

    if ('mfaRequired' in result) {
      return result;
    }

    return this.tokens.issueTokens({
      userId: result.userId,
      sessionId: result.sessionId,
      ipAddress: request.ipAddress,
      userAgent: request.userAgent,
    });
  }

  async completeMfa(request: {
    userId: string;
    sessionId: string;
    mfaCode: string;
    ipAddress: string;
    userAgent: string;
  }) {
    await this.credentials.verifyMfaCode({
      userId: request.userId,
      sessionId: request.sessionId,
      code: request.mfaCode,
    });

    return this.tokens.issueTokens({
      userId: request.userId,
      sessionId: request.sessionId,
      ipAddress: request.ipAddress,
      userAgent: request.userAgent,
    });
  }

  refresh(request: RefreshRequest) {
    return this.tokens.refreshTokens(request);
  }

  logout(request: { userId: string; sessionId: string; accessToken: string }) {
    return this.sessions.logoutCurrentSession(request);
  }

  logoutAll(request: { userId: string; accessToken: string }) {
    return this.sessions.logoutAllSessions(request);
  }

  requestPasswordReset(request: PasswordResetRequest) {
    return this.credentials.requestPasswordReset(request);
  }

  confirmPasswordReset(request: ConfirmPasswordResetRequest) {
    return this.credentials.confirmPasswordReset(request);
  }

  changePassword(request: ChangePasswordRequest) {
    return this.credentials.changePassword(request);
  }

  listSessions(userId: string) {
    return this.sessions.listSessions(userId);
  }

  revokeSession(request: {
    userId: string;
    sessionId: string;
    accessToken: string;
  }) {
    return this.sessions.revokeSession(request);
  }

  async loginWithGoogle(request: {
    idToken: string;
    ipAddress: string;
    userAgent: string;
  }) {
    await this.security.assertSocialLoginAllowed([
      `social:${AuthProvider.GOOGLE}:ip:${request.ipAddress}`,
    ]);

    let profile: SocialProfile;

    try {
      profile = await this.googleAuth.verifyIdToken(request.idToken);
    } catch (error) {
      await this.security.recordFailedSocialLogin([
        `social:${AuthProvider.GOOGLE}:ip:${request.ipAddress}`,
      ]);
      throw error;
    }

    return this.handleSocialLogin(AuthProvider.GOOGLE, profile, request);
  }


  async loginWithFacebook(request: {
    accessToken: string;
    ipAddress: string;
    userAgent: string;
  }) {
    await this.security.assertSocialLoginAllowed([
      `social:${AuthProvider.FACEBOOK}:ip:${request.ipAddress}`,
    ]);

    let profile: SocialProfile;

    try {
      profile = await this.facebookAuth.verifyAccessToken(
        request.accessToken,
      );
    } catch (error) {
      await this.security.recordFailedSocialLogin([
        `social:${AuthProvider.FACEBOOK}:ip:${request.ipAddress}`,
      ]);
      throw error;
    }

    return this.handleSocialLogin(AuthProvider.FACEBOOK, profile, request);
  }

  private async handleSocialLogin(
    provider: AuthProvider,
    profile: SocialProfile,
    context: { ipAddress: string; userAgent: string },
  ) {
    if (!profile.email || !profile.emailVerified) {
      throw new UnauthorizedException();
    }

    const identifiers = this.security.buildSocialIdentifiers({
      provider,
      providerUserId: profile.providerId,
      email: profile.email,
      ipAddress: context.ipAddress,
    });

    await this.security.assertSocialLoginAllowed(identifiers);

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
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });
  }

}
