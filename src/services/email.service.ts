
export interface EmailServiceConfig {
  provider: string;
  apiKey?: string;
  host?: string;
  port?: number;
  secure?: boolean;
  auth?: {
    user: string;
    pass: string;
  };
}

export class EmailService {
  private config: EmailServiceConfig;

  constructor(config: EmailServiceConfig) {
    this.config = config;
  }

  async sendOtp(email: string, otp: string): Promise<void> {
    try {
      // Implement your email sending logic here
      // This is a placeholder implementation
      console.log(`Sending OTP ${otp} to ${email}`);
      
      // For production, implement actual email sending:
      // - SendGrid
      // - AWS SES
      // - NodeMailer with SMTP
      // - etc.
      
      return Promise.resolve();
    } catch (error) {
      throw new Error(`Failed to send OTP: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async sendWelcomeEmail(email: string, name: string): Promise<void> {
    try {
      console.log(`Sending welcome email to ${name} (${email})`);
      return Promise.resolve();
    } catch (error) {
      throw new Error(`Failed to send welcome email: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async sendPasswordResetEmail(email: string, resetToken: string): Promise<void> {
    try {
      console.log(`Sending password reset email to ${email} with token ${resetToken}`);
      return Promise.resolve();
    } catch (error) {
      throw new Error(`Failed to send password reset email: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}
