import fs from 'fs';
import path from 'path';
import Handlebars from 'handlebars';
import { MailProvider } from './mail.provider';

export class MailService {
  constructor(private readonly provider: MailProvider) {}

  async sendEmailVerification(email: string, link: string): Promise<void> {
    await this.send({
      to: email,
      subject: 'Verify your email',
      template: 'verify-email',
      context: { link },
    });
  }

  async sendPasswordReset(email: string, link: string): Promise<void> {
    await this.send({
      to: email,
      subject: 'Reset your password',
      template: 'reset-password',
      context: { link },
    });
  }

  private async send(options: {
    to: string;
    subject: string;
    template: string;
    context: Record<string, any>;
  }): Promise<void> {
    const html = this.renderTemplate(options.template, options.context);
    await this.provider.send({
      to: options.to,
      subject: options.subject,
      html,
    });
  }

  private renderTemplate(template: string, context: any): string {
    const filePath = path.join(
      __dirname,
      'templates',
      `${template}.hbs`,
    );
    const source = fs.readFileSync(filePath, 'utf8');
    return Handlebars.compile(source)(context);
  }
}
