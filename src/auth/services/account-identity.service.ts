import {
  Injectable,
  BadRequestException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { MailService } from '../../mail/mail.service';
import { AuthProvider, MfaType } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as speakeasy from 'speakeasy';

const PASSWORD_REGEX =
  /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

function assertStrongPassword(password: string) {
  if (!PASSWORD_REGEX.test(password)) {
    throw new BadRequestException('Weak password');
  }
}

@Injectable()
export class AccountIdentityService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly mailService: MailService,
  ) { }

  async register(params: {
    email: string;
    password: string;
    confirmPassword: string;
    phone?: string;
    ipAddress: string;
    userAgent: string;
  }) {
    const { email, password, confirmPassword, phone } = params;
    const normalizedEmail = email.toLowerCase().trim();

    if (password !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    assertStrongPassword(password);

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
            providerId: normalizedEmail,
            passwordHash,
            isPrimary: true,
            verifiedAt: null,
          },
        },
        customerProfile: phone ? { create: { phone } } : undefined,
      },
    });

    const token = crypto.randomBytes(48).toString('hex');

    await this.prisma.emailVerification.create({
      data: {
        userId: user.id,
        email: normalizedEmail,
        token,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });

    await this.mailService.sendEmailVerification(
      normalizedEmail,
      `${process.env.FRONTEND_URL}/verify-email?token=${token}`,
    );

    return { success: true };
  }

  async verifyEmail(token: string) {
    const record = await this.prisma.emailVerification.findUnique({
      where: { token },
    });

    if (!record || record.expiresAt < new Date() || record.verifiedAt !== null) {
      throw new UnauthorizedException('Invalid verification token');
    }

    await this.prisma.$transaction([
      this.prisma.emailVerification.update({
        where: { id: record.id },
        data: { verifiedAt: new Date() },
      }),
      this.prisma.authAccount.updateMany({
        where: {
          userId: record.userId,
          provider: AuthProvider.LOCAL,
        },
        data: { verifiedAt: new Date() },
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

    if (!localAccount || localAccount.verifiedAt !== null) {
      throw new BadRequestException('Account already verified');
    }

    const token = crypto.randomBytes(48).toString('hex');

    await this.prisma.emailVerification.updateMany({
      where: {
        userId: user.id,
        verifiedAt: null,
      },
      data: {
        token,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });

    await this.mailService.sendEmailVerification(
      normalizedEmail,
      `${process.env.FRONTEND_URL}/verify-email?token=${token}`,
    );

    return { success: true };
  }

  async upsertSocialAccount(params: {
    provider: AuthProvider;
    providerId: string;
    email: string;
    emailVerified: boolean;
  }) {
    const normalizedEmail = params.email.toLowerCase().trim();

    return this.prisma.$transaction(async (tx) => {
      let user = await tx.user.findUnique({
        where: { email: normalizedEmail },
      });

      if (!user) {
        user = await tx.user.create({
          data: { email: normalizedEmail },
        });
      }

      const authAccount = await tx.authAccount.upsert({
        where: {
          provider_providerId: {
            provider: params.provider,
            providerId: params.providerId,
          },
        },
        update: {
          lastUsedAt: new Date(),
          verifiedAt: params.emailVerified ? new Date() : null,
        },
        create: {
          userId: user.id,
          provider: params.provider,
          providerId: params.providerId,
          isPrimary: false,
          verifiedAt: params.emailVerified ? new Date() : null,
        },
      });

      return { user, authAccount };
    });
  }

  async setupMfaTotp(userId: string) {
    const secret = speakeasy.generateSecret({ length: 20 });

    await this.prisma.mfaFactor.upsert({
      where: {
        userId_type: {
          userId,
          type: MfaType.TOTP,
        },
      },
      update: {
        secretHash: secret.base32,
        revokedAt: null,
      },
      create: {
        userId,
        type: MfaType.TOTP,
        secretHash: secret.base32,
      },
    });

    return {
      otpauthUrl: secret.otpauth_url,
      base32: secret.base32,
    };
  }

  async confirmMfaTotp(params: { userId: string; code: string }) {
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

    await this.prisma.mfaFactor.update({
      where: { id: factor.id },
      data: {
        verifiedAt: new Date(),
        lastUsedAt: new Date(),
      },
    });

    return { success: true };
  }
}
