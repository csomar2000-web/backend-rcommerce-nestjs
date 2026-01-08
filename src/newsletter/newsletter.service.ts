import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class NewsletterService {
  constructor(private prisma: PrismaService) {}

  async subscribe(email: string) {
    return this.prisma.newsletterSubscription.upsert({
      where: { email },
      update: { active: true },
      create: { email },
    });
  }

  async unsubscribe(email: string) {
    return this.prisma.newsletterSubscription.update({
      where: { email },
      data: { active: false },
    });
  }

  async findActive() {
    return this.prisma.newsletterSubscription.findMany({
      where: { active: true },
    });
  }
}
