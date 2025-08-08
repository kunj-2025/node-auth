import { celebrate } from 'celebrate';
import { Router } from 'express';
import { AuthController } from './auth.controller';
import { authValidation } from './auth.validation';
import { getConfig } from './config';

/**
 * @openapi
 * /register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *     responses:
 *       201:
 *         description: Registration successful
 *       400:
 *         description: Error
 *
 * /register/send-otp:
 *   post:
 *     summary: Send registration OTP
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP sent
 *       400:
 *         description: Error
 *
 * /register/verify:
 *   post:
 *     summary: Verify registration OTP
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               otp:
 *                 type: string
 *     responses:
 *       201:
 *         description: Email verified
 *       400:
 *         description: Error
 *
 * /login:
 *   post:
 *     summary: User login
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *       400:
 *         description: Error
 *
 * /admin/login:
 *   post:
 *     summary: Admin login
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Unauthorized
 *
 * /login/send-otp:
 *   post:
 *     summary: Send login OTP
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP sent
 *       400:
 *         description: Error
 *
 * /login/verify:
 *   post:
 *     summary: Verify login OTP
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               otp:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login verified
 *       400:
 *         description: Error
 *
 * /microsoft:
 *   get:
 *     summary: Initiate Microsoft SSO
 *     tags: [SSO]
 *     responses:
 *       302:
 *         description: Redirect to Microsoft
 *
 * /microsoft/callback:
 *   get:
 *     summary: Handle Microsoft SSO callback
 *     tags: [SSO]
 *     responses:
 *       302:
 *         description: Redirect to frontend
 *
 * /microsoft/token:
 *   post:
 *     summary: Exchange Microsoft code for token
 *     tags: [SSO]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               code:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token exchanged
 *       400:
 *         description: Error
 *
 * /webauthn/register/options:
 *   post:
 *     summary: Get WebAuthn registration options
 *     tags: [WebAuthn]
 *     responses:
 *       200:
 *         description: Registration options
 *       400:
 *         description: Error
 *
 * /webauthn/register/verify:
 *   post:
 *     summary: Verify WebAuthn registration
 *     tags: [WebAuthn]
 *     responses:
 *       200:
 *         description: Registration verified
 *       400:
 *         description: Error
 *
 * /webauthn/login/options:
 *   post:
 *     summary: Get WebAuthn login options
 *     tags: [WebAuthn]
 *     responses:
 *       200:
 *         description: Login options
 *       400:
 *         description: Error
 *
 * /webauthn/login/verify:
 *   post:
 *     summary: Verify WebAuthn login
 *     tags: [WebAuthn]
 *     responses:
 *       200:
 *         description: Login verified
 *       400:
 *         description: Error
 */
export function createAuthRoutes(): Router {
  const router = Router();
  const authController = new AuthController();
  const config = getConfig();

  router.post('/register', celebrate(authValidation.register), authController.register.bind(authController));
  router.post('/register/send-otp', celebrate(authValidation.sendOtp), authController.sendRegistrationOtp.bind(authController));
  router.post('/register/verify', celebrate(authValidation.verify), authController.verifyRegistrationOtp.bind(authController));
  router.post('/login', celebrate(authValidation.login), authController.login.bind(authController));
  router.post('/admin/login', celebrate(authValidation.login), authController.adminLogin.bind(authController));
  router.post('/login/send-otp', celebrate(authValidation.sendOtp), authController.sendLoginOtp.bind(authController));
  router.post('/login/verify', celebrate(authValidation.verify), authController.verifyLoginOtp.bind(authController));

  router.get('/microsoft', authController.microsoftSso.bind(authController));
  router.get('/microsoft/callback', authController.handleMicrosoftSsoCallback.bind(authController));
  router.post('/microsoft/token', authController.exchangeCodeForToken.bind(authController));

  // WebAuthn routes
  router.post('/webauthn/register/options', config.authenticate, authController.generateWebAuthnRegistrationOptions.bind(authController));
  router.post('/webauthn/register/verify', config.authenticate, authController.verifyWebAuthnRegistration.bind(authController));
  router.post('/webauthn/login/options', celebrate(authValidation.webAuthnLoginOptions), authController.generateWebAuthnLoginOptions.bind(authController));
  router.post('/webauthn/login/verify', celebrate(authValidation.webAuthnLoginVerify), authController.verifyWebAuthnLogin.bind(authController));

  return router;
}