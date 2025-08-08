
import { celebrate } from 'celebrate';
import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authValidation } from '../validation/auth.validation';
import { getConfig } from '../config';

export const createAuthRoutes = (): Router => {
  const router = Router();
  const controller = new AuthController();
  const config = getConfig();
  const { authenticate } = config;

  // Registration routes
  router.post('/register', celebrate(authValidation.register), controller.register.bind(controller));
  router.post('/register/send-otp', celebrate(authValidation.sendOtp), controller.sendRegistrationOtp.bind(controller));
  router.post('/register/verify', celebrate(authValidation.verify), controller.verifyRegistrationOtp.bind(controller));

  // Login routes
  router.post('/login', celebrate(authValidation.login), controller.login.bind(controller));
  router.post('/login/send-otp', celebrate(authValidation.sendOtp), controller.sendLoginOtp.bind(controller));
  router.post('/login/verify', celebrate(authValidation.verify), controller.verifyLoginOtp.bind(controller));

  // Admin routes
  router.post('/admin/login', celebrate(authValidation.login), controller.adminLogin.bind(controller));

  // Microsoft SSO routes
  router.get('/microsoft', controller.microsoftSso.bind(controller));
  router.get('/microsoft/callback', controller.handleMicrosoftSsoCallback.bind(controller));
  router.post('/microsoft/token', controller.exchangeCodeForToken.bind(controller));

  // WebAuthn routes (protected)
  router.post('/webauthn/register/options', authenticate, controller.generateWebAuthnRegistrationOptions.bind(controller));
  router.post('/webauthn/register/verify', authenticate, controller.verifyWebAuthnRegistration.bind(controller));
  router.post('/webauthn/login/options', celebrate(authValidation.webAuthnLoginOptions), controller.generateWebAuthnLoginOptions.bind(controller));
  router.post('/webauthn/login/verify', celebrate(authValidation.webAuthnLoginVerify), controller.verifyWebAuthnLogin.bind(controller));

  return router;
};
