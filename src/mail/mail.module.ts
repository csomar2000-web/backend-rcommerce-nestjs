import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { SmtpMailProvider } from './providers/smtp.provider';
import { ConsoleMailProvider } from './providers/console.provider';

@Module({
  providers: [
    {
      provide: 'MailProvider',
      useClass:
        process.env.NODE_ENV === 'production'
          ? SmtpMailProvider
          : ConsoleMailProvider,
    },
    {
      provide: MailService,
      inject: ['MailProvider'],
      useFactory: (provider) => new MailService(provider),
    },
  ],
  exports: [MailService],
})
export class MailModule {}
