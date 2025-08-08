
import { randomBytes } from 'crypto';
import jwt from 'jsonwebtoken';
import { User } from '../types';
import { JWT_EXPIRY } from './constants';

// Utility functions
export const generateOtp = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

export const generateAuthCode = (): string => {
  return randomBytes(32).toString('hex');
};

export const createJwtToken = (user: User, jwtSecret: string): string => {
  return jwt.sign(
    { id: user.id, email: user.email },
    jwtSecret,
    { expiresIn: JWT_EXPIRY }
  );
};

export const sanitizeUser = (user: User): Omit<User, 'password'> => {
  const { password, ...userWithoutPassword } = user as any;
  return userWithoutPassword;
};

export const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

export const generateSecureToken = (length: number = 32): string => {
  return randomBytes(length).toString('hex');
};

export const isTokenExpired = (token: string, secret: string): boolean => {
  try {
    jwt.verify(token, secret);
    return false;
  } catch (error) {
    return true;
  }
};
