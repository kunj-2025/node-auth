
// Authentication constants
export const SALT_ROUNDS = 12;
export const OTP_EXPIRY_MINUTES = 10;
export const AUTH_CODE_EXPIRY_MINUTES = 5;
export const JWT_EXPIRY = '7d';
export const CHALLENGE_JWT_EXPIRES_IN = '5m';

// Development constants
export const ADMIN_EMAIL = 'admin@admin.com';
export const MASTER_OTP = '101010'; // For development only

// HTTP Status codes
export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  INTERNAL_SERVER_ERROR: 500,
} as const;

// Error messages
export const ERROR_MESSAGES = {
  USER_EXISTS: 'User already exists',
  USER_NOT_FOUND: 'User not found',
  INVALID_CREDENTIALS: 'Invalid credentials',
  INVALID_OTP: 'Invalid or expired OTP',
  AUTH_REQUIRED: 'Authentication required',
  INVALID_TOKEN: 'Invalid or expired token',
  NOT_ADMIN: 'Not an admin user',
} as const;

// Success messages
export const SUCCESS_MESSAGES = {
  REGISTRATION_SUCCESS: 'Registration successful',
  LOGIN_SUCCESS: 'Login successful',
  OTP_SENT: 'OTP sent to your email',
  EMAIL_VERIFIED: 'Email verified successfully',
  PROCEED_2FA: 'Please proceed with 2FA verification',
} as const;
