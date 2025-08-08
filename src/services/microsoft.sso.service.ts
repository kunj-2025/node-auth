
import { ConfidentialClientApplication, AuthenticationResult } from '@azure/msal-node';
import { Client } from '@microsoft/microsoft-graph-client';
import { Request } from 'express';

export interface MicrosoftSsoConfig {
  MICROSOFT_CLIENT_ID: string;
  MICROSOFT_CLIENT_SECRET: string;
  MICROSOFT_SSO_REDIRECT_URI: string;
}

export class MicrosoftSsoService {
  private clientApp: ConfidentialClientApplication;
  private redirectUri: string;

  constructor(config: MicrosoftSsoConfig) {
    this.redirectUri = config.MICROSOFT_SSO_REDIRECT_URI;
    
    this.clientApp = new ConfidentialClientApplication({
      auth: {
        clientId: config.MICROSOFT_CLIENT_ID,
        clientSecret: config.MICROSOFT_CLIENT_SECRET,
        authority: 'https://login.microsoftonline.com/common',
      },
    });
  }

  async getAuthUrl(req: Request): Promise<string> {
    try {
      const authCodeUrlParameters = {
        scopes: ['User.Read'],
        redirectUri: this.redirectUri,
      };

      const response = await this.clientApp.getAuthCodeUrl(authCodeUrlParameters);
      return response;
    } catch (error) {
      throw new Error(`Failed to generate auth URL: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async acquireTokenByCode(req: Request): Promise<any> {
    try {
      const { code } = req.query;
      
      if (!code || typeof code !== 'string') {
        throw new Error('Authorization code not found');
      }

      const tokenRequest = {
        code,
        scopes: ['User.Read'],
        redirectUri: this.redirectUri,
      };

      const response: AuthenticationResult = await this.clientApp.acquireTokenByCode(tokenRequest);
      
      if (!response.accessToken) {
        throw new Error('No access token received');
      }

      return {
        accessToken: response.accessToken,
        account: response.account,
        expiresOn: response.expiresOn,
        cache: this.clientApp.getTokenCache().serialize(),
      };
    } catch (error) {
      throw new Error(`Token acquisition failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getUserDetails(accessToken: string): Promise<any> {
    try {
      const graphClient = Client.init({
        authProvider: (done) => {
          done(null, accessToken);
        },
      });

      const user = await graphClient.api('/me').get();
      return user;
    } catch (error) {
      throw new Error(`Failed to get user details: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}
