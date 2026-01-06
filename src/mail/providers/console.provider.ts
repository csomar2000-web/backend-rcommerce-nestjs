import { MailProvider } from '../mail.provider';

export class ConsoleMailProvider implements MailProvider {
  async send({ to, subject, html }: any): Promise<void> {
    process.stdout.write(
      JSON.stringify(
        {
          to,
          subject,
          html,
        },
        null,
        2,
      ) + '\n',
    );
  }
}
