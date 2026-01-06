import {
  Injectable,
  BadRequestException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { MailService } from '../../mail/mail.service';
import { MfaType, AuthProvider } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as speakeasy from 'speakeasy';

@Injectable()
export class AccountIdentityService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly mailService: MailService,
  ) { }

  /* ------------------------------------------------------------------
   * REGISTRATION
   * ------------------------------------------------------------------ */

  async register(params: {
    email: string;
    password: string;
    confirmPassword: string;
    phoneNumber: string;
    ipAddress: string;
    userAgent: string;
  }) {
    const {
      email,
      password,
      confirmPassword,
      phoneNumber,
      ipAddress,
      userAgent,
    } = params;

    const normalizedEmail = email.toLowerCase().trim();

    if (password !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    if (!/(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}/.test(password)) {
      throw new BadRequestException('Weak password');
    }

    const existingUser = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (existingUser) {
      throw new ConflictException('Email already in use');
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await this.prisma.user.create({
      data: {
        email: normalizedEmail,
        authAccounts: {
          create: {
            provider: AuthProvider.LOCAL,
            providerId: normalizedEmail, // ✅ REQUIRED BY PRISMA
            passwordHash,
            isPrimary: true,
            isVerified: false,
          },
        },
        customerProfile: {
          create: { phoneNumber },
        },
      },
    });

    const rawToken = crypto.randomBytes(48).toString('hex');
    const tokenHash = this.hashToken(rawToken);

    await this.prisma.emailVerification.create({
      data: {
        userId: user.id,
        email: normalizedEmail,
        tokenHash,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });

    await this.mailService.sendEmailVerification(
      normalizedEmail,
      `${process.env.FRONTEND_URL}/verify-email?token=${rawToken}`,
    );

    await this.prisma.userAuditLog.create({
      data: {
        userId: user.id,
        eventType: 'AUTH',
        eventAction: 'REGISTER',
        ipAddress,
        userAgent,
        success: true,
      },
    });

    return { success: true };
  }

  /* ------------------------------------------------------------------
   * EMAIL VERIFICATION
   * ------------------------------------------------------------------ */

  async verifyEmail(token: string) {
    const tokenHash = this.hashToken(token);

    const record = await this.prisma.emailVerification.findUnique({
      where: { tokenHash },
    });

    if (!record || record.expiresAt < new Date() || record.verified) {
      throw new UnauthorizedException('Invalid verification token');
    }

    await this.prisma.$transaction([
      this.prisma.emailVerification.update({
        where: { id: record.id },
        data: { verified: true, verifiedAt: new Date() },
      }),
      this.prisma.authAccount.updateMany({
        where: {
          userId: record.userId,
          provider: AuthProvider.LOCAL,
        },
        data: { isVerified: true },
      }),
    ]);

    return { success: true };
  }

  async resendVerification(email: string) {
    const normalizedEmail = email.toLowerCase().trim();

    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
      include: { authAccounts: true },
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    const localAccount = user.authAccounts.find(
      (a) => a.provider === AuthProvider.LOCAL,
    );

    if (!localAccount || localAccount.isVerified) {
      throw new BadRequestException('Account already verified');
    }

    const rawToken = crypto.randomBytes(48).toString('hex');
    const tokenHash = this.hashToken(rawToken);

    await this.prisma.emailVerification.updateMany({
      where: { userId: user.id, verified: false },
      data: {
        tokenHash,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        attempts: { increment: 1 },
      },
    });

    await this.mailService.sendEmailVerification(
      normalizedEmail,
      `${process.env.FRONTEND_URL}/verify-email?token=${rawToken}`,
    );

    return { success: true };
  }

  /* ------------------------------------------------------------------
   * MFA SETUP (TOTP)
   * ------------------------------------------------------------------ */

  async setupMfaTotp(userId: string) {
    const secret = speakeasy.generateSecret({ length: 20 });

    const secretHash = this.hashToken(secret.base32);

    await this.prisma.mfaFactor.upsert({
      where: {
        userId_type: {
          userId,
          type: MfaType.TOTP,
        },
      },
      update: {
        secretHash,
        isEnabled: false,
        revokedAt: null,
      },
      create: {
        userId,
        type: MfaType.TOTP,
        secretHash,
      },
    });

    return {
      otpauthUrl: secret.otpauth_url,
      base32: secret.base32,
    };
  }

  async confirmMfaTotp(params: {
    userId: string;
    code: string;
    ipAddress: string;
    userAgent: string;
  }) {
    const factor = await this.prisma.mfaFactor.findFirst({
      where: {
        userId: params.userId,
        type: MfaType.TOTP,
        revokedAt: null,
      },
    });

    if (!factor) {
      throw new BadRequestException('MFA not initialized');
    }

    const valid = speakeasy.totp.verify({
      secret: factor.secretHash,
      encoding: 'base32',
      token: params.code,
      window: 1,
    });

    if (!valid) {
      throw new UnauthorizedException('Invalid MFA code');
    }

    await this.prisma.$transaction([
      this.prisma.mfaFactor.update({
        where: { id: factor.id },
        data: {
          isEnabled: true,
          verifiedAt: new Date(),
          lastUsedAt: new Date(),
        },
      }),
      this.prisma.session.updateMany({
        where: { userId: params.userId },
        data: {
          isActive: false,
          invalidatedAt: new Date(),
          invalidationReason: 'MFA_ENABLED',
        },
      }),
    ]);

    await this.prisma.userAuditLog.create({
      data: {
        userId: params.userId,
        eventType: 'SECURITY',
        eventAction: 'MFA_ENABLED',
        ipAddress: params.ipAddress,
        userAgent: params.userAgent,
        success: true,
      },
    });

    return { success: true };
  }

  /* ------------------------------------------------------------------
   * HELPERS
   * ------------------------------------------------------------------ */

  private hashToken(value: string): string {
    return crypto.createHash('sha256').update(value).digest('hex');
  }
}
