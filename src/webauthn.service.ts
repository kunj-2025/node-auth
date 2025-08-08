import {
    AuthenticatorTransportFuture,
    generateAuthenticationOptions, generateRegistrationOptions, VerifiedAuthenticationResponse,
    VerifiedRegistrationResponse, verifyAuthenticationResponse, verifyRegistrationResponse
} from '@simplewebauthn/server';
import { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/types';
import jwt from 'jsonwebtoken';

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

    async getRegistrationOptions(user: any) {
        const userAuthenticators = await this.prisma.passkey.findMany({
            where: { userId: user.id },
        });
        const options = await generateRegistrationOptions({
            rpName: this.rpName,
            rpID: this.rpID,
            userID: Buffer.from(user.id),
            userName: user.email,
            attestationType: 'none',
            excludeCredentials: userAuthenticators.map((auth: any) => ({
                id: auth.credentialID,
                type: 'public-key',
                transports: auth.transports?.split(',') as AuthenticatorTransportFuture[],
            })),
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred',
            },
        });
        return options;
    }

    async verifyRegistration(user: any, body: RegistrationResponseJSON, expectedChallenge: string): Promise<boolean> {
        if (!expectedChallenge) {
            throw new Error('Challenge not provided for verification');
        }
        const verification: VerifiedRegistrationResponse = await verifyRegistrationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: this.origin,
            expectedRPID: this.rpID,
            requireUserVerification: false,
        });
        const { verified, registrationInfo } = verification;
        if (verified && registrationInfo) {
            const info = registrationInfo;
            await this.prisma.passkey.create({
                data: {
                    user: { connect: { id: user.id } },
                    credentialID: body.id,
                    publicKey: Buffer.from(info.credential.publicKey),
                    counter: info.credential.counter,
                    deviceType: info.credentialDeviceType,
                    backedUp: info.credentialBackedUp,
                    transports: info.credential.transports?.join(','),
                }
            });
        }
        return verified;
    }

    async getLoginOptions(email: string) {
        const user = await this.prisma.user.findUnique({
            where: { email },
            include: { passkeys: true },
        });
        if (!user) {
            throw new Error('User not found');
        }
        const options = await generateAuthenticationOptions({
            rpID: this.rpID,
            allowCredentials: user.passkeys.map((passkey: any) => ({
                id: passkey.credentialID,
                type: 'public-key',
                transports: passkey.transports?.split(',') as AuthenticatorTransportFuture[],
            })),
            userVerification: 'preferred',
        });
        return options;
    }

    async verifyLogin(body: AuthenticationResponseJSON, expectedChallenge: string, email: string) {
        const user = await this.prisma.user.findUnique({
            where: { email },
            include: { passkeys: true },
        });
        if (!user) {
            throw new Error('User not found');
        }
        const passkey = user.passkeys.find((pk: any) => pk.credentialID === body.id);
        if (!passkey) {
            throw new Error('Passkey not found for this user.');
        }
        let verification: VerifiedAuthenticationResponse;
        try {
            verification = await verifyAuthenticationResponse({
                response: body,
                expectedChallenge,
                expectedOrigin: this.origin,
                expectedRPID: this.rpID,
                credential: {
                    id: passkey.credentialID,
                    publicKey: passkey.publicKey,
                    counter: passkey.counter,
                },
                requireUserVerification: false,
            });
        } catch (error) {
            return { success: false, error: (error as Error).message };
        }
        if (verification.verified) {
            await this.prisma.passkey.update({
                where: { id: passkey.id },
                data: { counter: verification.authenticationInfo.newCounter },
            });
            const token = jwt.sign({ id: user.id, email: user.email }, this.jwtSecret, {
                expiresIn: '7d'
            });
            return { success: true, token, user };
        }
        return { success: false };
    }
} 