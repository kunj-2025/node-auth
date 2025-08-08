
import {
    AuthenticatorTransportFuture,
    generateAuthenticationOptions, generateRegistrationOptions, VerifiedAuthenticationResponse,
    VerifiedRegistrationResponse, verifyAuthenticationResponse, verifyRegistrationResponse
} from '@simplewebauthn/server';
import { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/types';
import jwt from 'jsonwebtoken';
import { User } from '../types';

export interface WebAuthnConfig {
    RP_NAME: string;
    RP_ID: string;
    FRONTEND_URL: string;
    JWT_SECRET: string;
}

export class WebAuthnService {
    private rpName: string;
    private rpID: string;
    private origin: string;
    private jwtSecret: string;
    private prisma: any;

    constructor({ config, prisma }: { config: WebAuthnConfig, prisma: any }) {
        this.rpName = config.RP_NAME;
        this.rpID = config.RP_ID;
        this.origin = config.FRONTEND_URL;
        this.jwtSecret = config.JWT_SECRET;
        this.prisma = prisma;
    }

    async getRegistrationOptions(user: User) {
        try {
            const existingPasskeys = await this.prisma.passkey.findMany({
                where: { userId: user.id },
            });

            const excludeCredentials = existingPasskeys.map((passkey: any) => ({
                id: new Uint8Array(Buffer.from(passkey.credentialID, 'base64url')),
                type: 'public-key' as const,
                transports: passkey.transports ? JSON.parse(passkey.transports) : undefined,
            }));

            const options = await generateRegistrationOptions({
                rpName: this.rpName,
                rpID: this.rpID,
                userID: new TextEncoder().encode(user.id),
                userName: user.email,
                userDisplayName: user.name || user.email,
                attestationType: 'none',
                excludeCredentials,
                authenticatorSelection: {
                    userVerification: 'preferred',
                    residentKey: 'preferred',
                },
            });

            return options;
        } catch (error) {
            throw new Error(`Failed to generate registration options: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    async verifyRegistration(user: User, registrationData: RegistrationResponseJSON, expectedChallenge: string): Promise<boolean> {
        try {
            const verification: VerifiedRegistrationResponse = await verifyRegistrationResponse({
                response: registrationData,
                expectedChallenge,
                expectedOrigin: this.origin,
                expectedRPID: this.rpID,
                requireUserVerification: false,
            });

            if (verification.verified && verification.registrationInfo) {
                const { credentialID, credentialPublicKey, counter, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

                await this.prisma.passkey.create({
                    data: {
                        userId: user.id,
                        credentialID: Buffer.from(credentialID).toString('base64url'),
                        credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
                        counter,
                        credentialDeviceType,
                        credentialBackedUp,
                    },
                });

                return true;
            }

            return false;
        } catch (error) {
            throw new Error(`Registration verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    async getLoginOptions(email: string) {
        try {
            const user = await this.prisma.user.findUnique({
                where: { email },
                include: { passkeys: true },
            });

            if (!user || user.passkeys.length === 0) {
                throw new Error('No passkeys found for this user');
            }

            const allowCredentials = user.passkeys.map((passkey: any) => ({
                id: new Uint8Array(Buffer.from(passkey.credentialID, 'base64url')),
                type: 'public-key' as const,
                transports: passkey.transports ? JSON.parse(passkey.transports) : undefined,
            }));

            const options = await generateAuthenticationOptions({
                rpID: this.rpID,
                allowCredentials,
                userVerification: 'preferred',
            });

            return options;
        } catch (error) {
            throw new Error(`Failed to generate login options: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    async verifyLogin(authenticationData: AuthenticationResponseJSON, expectedChallenge: string, email: string) {
        try {
            const user = await this.prisma.user.findUnique({
                where: { email },
                include: { passkeys: true },
            });

            if (!user) {
                throw new Error('User not found');
            }

            const passkey = user.passkeys.find((p: any) => 
                p.credentialID === Buffer.from(authenticationData.rawId, 'base64url').toString('base64url')
            );

            if (!passkey) {
                throw new Error('Passkey not found');
            }

            const verification: VerifiedAuthenticationResponse = await verifyAuthenticationResponse({
                response: authenticationData,
                expectedChallenge,
                expectedOrigin: this.origin,
                expectedRPID: this.rpID,
                authenticator: {
                    credentialID: new Uint8Array(Buffer.from(passkey.credentialID, 'base64url')),
                    credentialPublicKey: new Uint8Array(Buffer.from(passkey.credentialPublicKey, 'base64url')),
                    counter: passkey.counter,
                    transports: passkey.transports ? JSON.parse(passkey.transports) : undefined,
                },
                requireUserVerification: false,
            });

            if (verification.verified) {
                await this.prisma.passkey.update({
                    where: { id: passkey.id },
                    data: { counter: verification.authenticationInfo.newCounter },
                });

                const token = jwt.sign(
                    { id: user.id, email: user.email },
                    this.jwtSecret,
                    { expiresIn: '7d' }
                );

                return {
                    success: true,
                    user: { id: user.id, email: user.email, name: user.name },
                    token,
                };
            }

            return { success: false };
        } catch (error) {
            throw new Error(`Login verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
}
