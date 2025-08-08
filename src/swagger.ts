import swaggerUi from 'swagger-ui-express';
import swaggerJSDoc from 'swagger-jsdoc';
import { Router } from 'express';

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'Auth API',
    version: '1.0.0',
    description: 'Authentication API (register, login, OTP, SSO, WebAuthn)'
  },
  servers: [
    {
      url: '/auth',
      description: 'Auth API base path'
    }
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
  },
  security: [{ bearerAuth: [] }],
};

const options = {
  swaggerDefinition,
  apis: ['./src/auth.routes.ts'], // You can add more files for JSDoc comments
};

const swaggerSpec = swaggerJSDoc(options);

export function getAuthSwaggerRouter(): Router {
  const router = Router();
  router.use('/', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  return router;
} 