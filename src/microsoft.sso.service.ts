import { Request } from "express";
import { AuthorizationCodeRequest, AuthorizationUrlRequest, ConfidentialClientApplication, CryptoProvider } from "@azure/msal-node";
import { Client } from "@microsoft/microsoft-graph-client";
import "isomorphic-fetch";

export interface MicrosoftSsoConfig {
    MICROSOFT_CLIENT_ID: string;
    MICROSOFT_CLIENT_SECRET: string;
    MICROSOFT_SSO_REDIRECT_URI: string;
}

const SSO_SCOPES = ["https://graph.microsoft.com/User.Read"];

export class MicrosoftSsoService {
    private cca: ConfidentialClientApplication;
    private cryptoProvider: CryptoProvider;
    private config: MicrosoftSsoConfig;

    constructor(config: MicrosoftSsoConfig) {
        this.config = config;
        const msalConfig = {
            auth: {
                clientId: config.MICROSOFT_CLIENT_ID,
                authority: "https://login.microsoftonline.com/common",
                clientSecret: config.MICROSOFT_CLIENT_SECRET,
            },
        };
        this.cca = new ConfidentialClientApplication(msalConfig);
        this.cryptoProvider = new CryptoProvider();
    }

    async getAuthUrl(session: any): Promise<string | null> {
        try {
            const { verifier, challenge } = await this.cryptoProvider.generatePkceCodes();
            const authCodeUrlParameters: AuthorizationUrlRequest = {
                scopes: SSO_SCOPES,
                redirectUri: this.config.MICROSOFT_SSO_REDIRECT_URI,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            };
            session.pkceCodes = { verifier, challenge };
            const authUrl = await this.cca.getAuthCodeUrl(authCodeUrlParameters);
            return authUrl;
        } catch (error) {
            return null;
        }
    }

    async acquireTokenByCode(req: Request): Promise<any> {
        console.log("req session", req.session)
        const tokenRequest: AuthorizationCodeRequest = {
            code: req.query.code as string,
            scopes: SSO_SCOPES,
            redirectUri: this.config.MICROSOFT_SSO_REDIRECT_URI,
            codeVerifier: req.session.pkceCodes?.verifier,
        };

        try {
            const response = await this.cca.acquireTokenByCode(tokenRequest);
            if (response) {
                const cache = this.cca.getTokenCache().serialize();
                return { ...response, cache };
            }
            return null;
        } catch (error) {
            console.log(error);
            return null;
        }
    }


    getAuthenticatedClient(accessToken: string): Client {
        return Client.init({
            authProvider: (done) => {
                done(null, accessToken);
            },
        });
    }

    async getUserDetails(accessToken: string): Promise<any> {
        const client = this.getAuthenticatedClient(accessToken);
        return client.api("/me").get();
    }
}