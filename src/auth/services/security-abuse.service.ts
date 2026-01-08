import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

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

@Injectable()
export class SecurityAbuseService {
  constructor(private readonly prisma: PrismaService) { }

  async assertLoginAllowed(params: { identifier: string }) {
    const now = new Date();

    const activeBlock = await this.prisma.rateLimit.findFirst({
      where: {
        identifier: params.identifier,
        action: 'LOGIN_BLOCK',
        expiresAt: { gt: now },
      },
    });

    if (activeBlock) {
      throw new ForbiddenException('Temporarily blocked');
    }

    const windowStart = bucket(now, LOGIN_WINDOW_MINUTES);

    const record = await this.prisma.rateLimit.findUnique({
      where: {
        identifier_action_windowStart: {
          identifier: params.identifier,
          action: 'LOGIN',
          windowStart,
        },
      },
    });

    if ((record?.count ?? 0) >= LOGIN_LIMIT) {
      await this.blockIdentifier(params.identifier);
      throw new ForbiddenException('Temporarily blocked');
    }
  }

  async recordFailedLogin(params: {
    identifier: string;
    ipAddress: string;
    userAgent: string;
  }) {
    const now = new Date();
    const windowStart = bucket(now, LOGIN_WINDOW_MINUTES);

    await this.prisma.rateLimit.upsert({
      where: {
        identifier_action_windowStart: {
          identifier: params.identifier,
          action: 'LOGIN',
          windowStart,
        },
      },
      create: {
        identifier: params.identifier,
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

  async clearLoginFailures(identifier: string) {
    await this.prisma.rateLimit.deleteMany({
      where: {
        identifier,
        action: 'LOGIN',
      },
    });
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
