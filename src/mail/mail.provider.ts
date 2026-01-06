export interface MailProvider {
  send(options: {
    to: string;
    subject: string;
    html: string;
    text?: string;
  }): Promise<void>;
}
