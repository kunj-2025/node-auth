import { Joi } from 'celebrate';

export const authValidation = {
    register: {
        body: Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().min(6).required(),
            name: Joi.string().required(),
        })
    },
    sendOtp: {
        body: Joi.object({
            email: Joi.string().email().required(),
        })
    },
    login: {
        body: Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().required(),
        })
    },
    verify: {
        body: Joi.object({
            email: Joi.string().email().required(),
            otp: Joi.string().length(6).required(),
        })
    },
    webAuthnLoginOptions: {
        body: Joi.object({
            email: Joi.string().email().required(),
        })
    },
    webAuthnLoginVerify: {
        body: Joi.object({
            email: Joi.string().email().required(),
            data: Joi.object().required(),
            challengeToken: Joi.string().required(),
        })
    }
}; 