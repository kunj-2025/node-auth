import { Client } from "@microsoft/microsoft-graph-client";
import axios from 'axios';

export interface EmailServiceConfig {
    MICROSOFT_TENANT_ID: string;
    MICROSOFT_SENDER_CLIENT_ID: string;
    MICROSOFT_SENDER_CLIENT_SECRET: string;
    MICROSOFT_SENDER_EMAIL: string;
}

export class EmailService {
    private config: EmailServiceConfig;
    constructor(config: EmailServiceConfig) {
        this.config = config;
    }

    public setConfig(config: EmailServiceConfig) {
        this.config = config;
    }

    private async getAccessToken(): Promise<string> {
        const url = `https://login.microsoftonline.com/${this.config.MICROSOFT_TENANT_ID}/oauth2/v2.0/token`;
        const body = new URLSearchParams({
            client_id: this.config.MICROSOFT_SENDER_CLIENT_ID,
            scope: 'https://graph.microsoft.com/.default',
            client_secret: this.config.MICROSOFT_SENDER_CLIENT_SECRET,
            grant_type: 'client_credentials',
        });
        const { data } = await axios.post(url, body, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
        return data.access_token;
    }

    async sendOtp(to: string, otp: string): Promise<void> {
        const accessToken = await this.getAccessToken();
        const client = Client.init({
            authProvider: (done) => done(null, accessToken),
        });
        await client.api(`/users/${this.config.MICROSOFT_SENDER_EMAIL}/sendMail`).post({
            message: {
                subject: 'Your OTP Code',
                body: {
                    contentType: 'Text',
                    content: `Your one-time password is: ${otp}. It is valid for 5 minutes.`,
                },
                toRecipients: [{ emailAddress: { address: to } }],
            },
            saveToSentItems: 'false',
        });
    }
}
