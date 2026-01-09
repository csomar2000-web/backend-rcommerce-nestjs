import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { AuthProvider } from '@prisma/client';

const LOGIN_LIMIT = 5;
const LOGIN_WINDOW_MINUTES = 15;
const BLOCK_MINUTES = 30;

const SENSITIVE_LIMIT = 3;
const SENSITIVE_WINDOW_MINUTES = 60;

type SensitiveActionType =
  | 'PASSWORD_RESET'
  | 'EMAIL_VERIFICATION'
  | 'MFA_SETUP';

function bucket(date: Date, minutes: number) {
  const ms = minutes * 60 * 1000;
  return new Date(Math.floor(date.getTime() / ms) * ms);
}

function passwordLoginIdentifiers(email: string, ip: string) {
  return [
    `login:email:${email}`,
    `login:ip:${ip}`,
    `login:email_ip:${email}:${ip}`,
  ];
}

function socialLoginIdentifiers(params: {
  provider: AuthProvider;
  providerUserId: string;
  email?: string | null;
  ipAddress: string;
}) {
  const ids = [
    `social:${params.provider}:user:${params.providerUserId}`,
    `social:${params.provider}:ip:${params.ipAddress}`,
  ];

  if (params.email) {
    ids.push(`social:${params.provider}:email:${params.email}`);
    ids.push(
      `social:${params.provider}:email_ip:${params.email}:${params.ipAddress}`,
    );
  }

  return ids;
}


@Injectable()
export class SecurityAbuseService {
  constructor(private readonly prisma: PrismaService) {}

  private async assertIdentifiersAllowed(identifiers: string[]) {
    const now = new Date();
    const windowStart = bucket(now, LOGIN_WINDOW_MINUTES);

    for (const identifier of identifiers) {
      const activeBlock = await this.prisma.rateLimit.findFirst({
        where: {
          identifier,
          action: 'LOGIN_BLOCK',
          expiresAt: { gt: now },
        },
      });

      if (activeBlock) {
        throw new ForbiddenException('Temporarily blocked');
      }

      const record = await this.prisma.rateLimit.findUnique({
        where: {
          identifier_action_windowStart: {
            identifier,
            action: 'LOGIN',
            windowStart,
          },
        },
      });

      if ((record?.count ?? 0) >= LOGIN_LIMIT) {
        await this.blockIdentifier(identifier);
        throw new ForbiddenException('Temporarily blocked');
      }
    }
  }

  private async recordFailure(identifiers: string[]) {
    const now = new Date();
    const windowStart = bucket(now, LOGIN_WINDOW_MINUTES);

    for (const identifier of identifiers) {
      await this.prisma.rateLimit.upsert({
        where: {
          identifier_action_windowStart: {
            identifier,
            action: 'LOGIN',
            windowStart,
          },
        },
        create: {
          identifier,
          action: 'LOGIN',
          windowStart,
          expiresAt: new Date(
            windowStart.getTime() + LOGIN_WINDOW_MINUTES * 60 * 1000,
          ),
          count: 1,
        },
        update: {
          count: { increment: 1 },
        },
      });
    }
  }


  async assertLoginAllowed(params: { email: string; ipAddress: string }) {
    const ids = passwordLoginIdentifiers(
      params.email,
      params.ipAddress,
    );
    await this.assertIdentifiersAllowed(ids);
  }

  async recordFailedLogin(params: {
    email: string;
    ipAddress: string;
  }) {
    const ids = passwordLoginIdentifiers(
      params.email,
      params.ipAddress,
    );
    await this.recordFailure(ids);
  }

  async clearLoginFailures(email: string, ipAddress: string) {
    const ids = passwordLoginIdentifiers(email, ipAddress);

    await this.prisma.rateLimit.deleteMany({
      where: {
        identifier: { in: ids },
        action: 'LOGIN',
      },
    });
  }

  async assertSocialLoginAllowed(identifiers: string[]) {
    await this.assertIdentifiersAllowed(identifiers);
  }

  async recordFailedSocialLogin(identifiers: string[]) {
    await this.recordFailure(identifiers);
  }

  buildSocialIdentifiers(params: {
    provider: AuthProvider;
    providerUserId: string;
    email?: string | null;
    ipAddress: string;
  }) {
    return socialLoginIdentifiers(params);
  }

  async blockIdentifier(identifier: string) {
    const now = new Date();
    const windowStart = bucket(now, BLOCK_MINUTES);

    await this.prisma.rateLimit.upsert({
      where: {
        identifier_action_windowStart: {
          identifier,
          action: 'LOGIN_BLOCK',
          windowStart,
        },
      },
      create: {
        identifier,
        action: 'LOGIN_BLOCK',
        windowStart,
        expiresAt: new Date(
          windowStart.getTime() + BLOCK_MINUTES * 60 * 1000,
        ),
        count: 1,
      },
      update: {
        count: { increment: 1 },
      },
    });
  }


  async assertSensitiveActionAllowed(params: {
    identifier: string;
    type: SensitiveActionType;
  }) {
    const now = new Date();
    const windowStart = bucket(now, SENSITIVE_WINDOW_MINUTES);

    const record = await this.prisma.rateLimit.findUnique({
      where: {
        identifier_action_windowStart: {
          identifier: params.identifier,
          action: params.type,
          windowStart,
        },
      },
    });

    if ((record?.count ?? 0) >= SENSITIVE_LIMIT) {
      throw new ForbiddenException('Too many requests');
    }

    await this.prisma.rateLimit.upsert({
      where: {
        identifier_action_windowStart: {
          identifier: params.identifier,
          action: params.type,
          windowStart,
        },
      },
      create: {
        identifier: params.identifier,
        action: params.type,
        windowStart,
        expiresAt: new Date(
          windowStart.getTime() + SENSITIVE_WINDOW_MINUTES * 60 * 1000,
        ),
        count: 1,
      },
      update: {
        count: { increment: 1 },
      },
    });
  }
}
