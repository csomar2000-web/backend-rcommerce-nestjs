import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class NewsletterService {
  constructor(private readonly prisma: PrismaService) { }

  async subscribe(email: string) {
    return this.prisma.newsletterSubscription.upsert({
      where: { email },
      update: {
        active: true,
        unsubscribedAt: null,
      },
      create: {
        email,
        active: true,
      },
    });
  }

  async unsubscribe(email: string) {
    await this.prisma.newsletterSubscription.updateMany({
      where: { email, active: true },
      data: {
        active: false,
        unsubscribedAt: new Date(),
      },
    });

    return { success: true };
  }

  async findActive() {
    return this.prisma.newsletterSubscription.findMany({
      where: { active: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findAll(active?: boolean) {
    return this.prisma.newsletterSubscription.findMany({
      where: active === undefined ? {} : { active },
      orderBy: { createdAt: 'desc' },
    });
  }

  async export(active?: boolean) {
    return this.prisma.newsletterSubscription.findMany({
      where: active === undefined ? {} : { active },
      select: {
        email: true,
        active: true,
        createdAt: true,
        unsubscribedAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });
  }
}
