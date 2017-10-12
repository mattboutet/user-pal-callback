'use strict';

const Joi = require('joi');
const Boom = require('boom');
const SecurePassword = require('secure-password');
const JWT = require('jsonwebtoken');
const Uuid = require('uuid');

//new instance of SecurePassword using the default config
const Pwd = new SecurePassword();

const internals = {};

module.exports = (server, options) => {

    return [
        {
            method: 'POST',
            path: '/login',
            config: {
                description: 'Log in',
                tags: ['api'],
                validate: {
                    payload: {
                        email: Joi.string().email().required(),
                        password: Joi.string().required()
                    }
                },
                auth: false
            },
            handler: (request, reply) => {

                const { Tokens, Users } = request.models();
                const Payload = request.payload;

                Users.query()
                    .where({ email: Payload.email })
                    .first()
                    .asCallback((userErr, foundUser) => {

                        if (userErr) {
                            return reply(userErr);
                        }

                        if (!foundUser) {
                            return reply(Boom.unauthorized('User or Password is invalid'));
                        }
                        const userPassword = Buffer.from(Payload.password);
                        const hash = Buffer.from(foundUser.password);

                        Pwd.verify(userPassword, hash, (verifyErr, result) => {

                            if (verifyErr) {
                                return reply(verifyErr);
                            }

                            if (result === SecurePassword.INVALID_UNRECOGNIZED_HASH ||
                                result === SecurePassword.INVALID) {
                                return reply(Boom.unauthorized('User or Password is invalid'));
                            }
                            else if (result === SecurePassword.VALID) {

                                const secret = options.jwtKey;

                                Tokens.query().insertAndFetch({})
                                    .asCallback((tokenErr, newToken) => {

                                        if (tokenErr) {
                                            return reply(tokenErr);
                                        }

                                        newToken.$relatedQuery('user').relate(foundUser)
                                            .asCallback((relatedErr) => {

                                                if (relatedErr) {
                                                    return reply(relatedErr);
                                                }

                                                const signed = JWT.sign({
                                                    jti: newToken.id,
                                                    user: foundUser.id
                                                }, secret);

                                                return reply(signed);
                                            });
                                    });
                            }
                            //password is valid, but hash used is now considered unsafe.
                            //Rehash with updated settings to bring it up to current standard
                            else if (result === SecurePassword.VALID_NEEDS_REHASH){

                                Pwd.hash(userPassword, (hashErr, newHash) => {

                                    if (hashErr) {
                                        return reply(hashErr);
                                    }
                                    Users.query()
                                        .patch({ 'password': newHash.toString('utf8') })
                                        .findById(foundUser.id)
                                        .asCallback((patchErr, patchedUser) => {

                                            if (patchErr){
                                                return reply(patchErr);
                                            }
                                            const secret = options.jwtKey;

                                            Tokens.query().insertAndFetch({})
                                                .asCallback((tokenErr, newToken) => {

                                                    if (tokenErr) {
                                                        return reply(tokenErr);
                                                    }

                                                    newToken.$relatedQuery('user').relate(foundUser)
                                                        .asCallback((relatedErr) => {

                                                            if (relatedErr) {
                                                                return reply(relatedErr);
                                                            }

                                                            const signed = JWT.sign({
                                                                jti: newToken.id,
                                                                user: foundUser.id
                                                            }, secret);

                                                            return reply(signed);
                                                        });
                                                });
                                        });
                                });
                            }
                        });
                    });
            }
        },
        {
            method: 'GET',
            path: '/users/{id}',
            config: {
                description: 'Get a user',
                tags: ['api'],
                validate: {
                    params: {
                        id: Joi.any().required()
                    }
                },
                auth: false
            },
            handler: { tandy: {} }
        },
        {
            method: 'GET',
            path: '/user',
            config: {
                description: 'Get logged-in user',
                tags: ['api'],
                validate: {
                    headers: Joi.object({
                        authorization: Joi.string()
                            .description('JWT')
                    }).unknown()
                },
                auth: {
                    strategy: 'api-user-jwt'
                }
            },
            handler: { tandy: {} }
        },
        {
            method: 'GET',
            path: '/users',
            config: {
                description: 'Get all users',
                tags: ['api'],
                validate: {
                    headers: Joi.object({
                        authorization: Joi.string()
                            .description('JWT')
                    }).unknown()
                },
                auth: {
                    strategy: 'api-user-jwt'
                }
            },
            handler: { tandy: {} }
        },
        {
            method: 'POST',
            path: '/users/request-reset',
            config: {
                description: 'Request password reset for a user',
                tags: ['api'],
                validate: {
                    payload: {
                        email: Joi.string().email().required()
                    }
                },
                auth: false
            },
            handler: (request, reply) => {

                const Users = request.models().Users;
                const Payload = request.payload;

                const rawResetToken = Buffer.from(Uuid({ rng: Uuid.nodeRNG }));

                Pwd.hash(rawResetToken, (err, hash) => {

                    if (err) {
                        return reply(err);
                    }
                    Users.query()
                        .patch(
                            {
                                'password': null,
                                resetToken: hash.toString('utf8')
                            }
                        )
                        .where({ 'email': Payload.email })
                        .asCallback((userErr, numFound) => {

                            if (userErr){
                                return reply(userErr);
                            }
                            //send token to user via email here. This functionality
                            //intentionally left out, as it is dependent on
                            //infrastructure and front end implementation.
                            return reply('Check your email for a reset link. TODO: Implement email sending');
                        });
                });
            }
        },
        {
            method: 'POST',
            path: '/users/reset-password',
            config: {
                description: 'Reset password for a user',
                tags: ['api'],
                validate: {
                    payload: {
                        email: Joi.string().email().required(),
                        resetToken: Joi.string().required(),
                        newPassword: Joi.string().required()
                    }
                },
                auth: false
            },
            handler: (request, reply) => {

                const { Users } = request.models();
                const Payload = request.payload;

                Users.query()
                    .where({ email: Payload.email })
                    .first()
                    .asCallback((err, foundUser) => {

                        if (err) {
                            return reply(err);
                        }
                        if (!foundUser) {
                            return reply(Boom.notFound('User not found'));
                        }

                        const userToken = Buffer.from(Payload.resetToken);
                        const hashToken = Buffer.from(foundUser.resetToken);

                        Pwd.verify(userToken, hashToken, (verifyErr, result) => {

                            if (verifyErr) {
                                return reply(verifyErr);
                            }

                            if (result === SecurePassword.INVALID_UNRECOGNIZED_HASH ||
                                result === SecurePassword.INVALID) {
                                return reply(Boom.unauthorized('Token is invalid'));
                            }
                            if (result === SecurePassword.VALID ||
                                result === SecurePassword.VALID_NEEDS_REHASH) {
                                const newPassword = Buffer.from(Payload.newPassword);

                                Pwd.hash(newPassword, (hashErr, newHash) => {

                                    if (hashErr) {
                                        return reply(hashErr);
                                    }
                                    Users.query()
                                        .patch({
                                            'password': newHash.toString('utf8'),
                                            'resetToken': null
                                        })
                                        .findById(foundUser.id)
                                        .asCallback((userErr, patchedUser) => {

                                            if (userErr){
                                                return reply(userErr);
                                            }
                                            return reply('Success');
                                        });
                                });
                            }//don't bother with rehash, since we're nulling out the token anyway
                            else {
                                return reply(Boom.unauthorized('Token is invalid'));
                            }
                        });
                    });
            }
        },
        {
            method: 'POST',
            path: '/users',
            config: {
                description: 'Register new user',
                tags: ['api'],
                validate: {
                    payload: {
                        email: Joi.string().email().required(),
                        password: Joi.string().required(),
                        firstName: Joi.string().required(),
                        lastName: Joi.string().required()
                    }
                },
                auth: false
            },
            handler: (request, reply) => {

                const Users = request.models().Users;
                const Payload = request.payload;

                const userPassword = Buffer.from(Payload.password);
                Pwd.hash(userPassword, (err, hash) => {

                    if (err) {
                        return reply(err);
                    }
                    Users.query()
                        .insertAndFetch({
                            email: Payload.email,
                            password: hash.toString('utf8'),
                            firstName: Payload.firstName,
                            lastName: Payload.lastName
                        })
                        .asCallback((error, user) => {

                            if (error){
                                return reply(error);
                            }

                            return reply(user).code(201);
                        });
                });
            }
        },
        {
            method: 'DELETE',
            path: '/users/{id}',
            config: {
                description: 'Delete a user',
                tags: ['api'],
                validate: {
                    headers: Joi.object({
                        authorization: Joi.string()
                            .description('JWT')
                    }).unknown(),
                    params: {
                        id: Joi.number().integer().required()
                    }
                },
                auth: {
                    strategy: 'api-user-jwt'
                }
            },
            handler: { tandy: {} }
        },
        {
            method: 'POST',
            path: '/users/change-password',
            config: {
                description: 'Change password of logged-in user',
                tags: ['api'],
                validate: {
                    headers: Joi.object({
                        authorization: Joi.string()
                            .description('JWT')
                    }).unknown(),
                    payload: {
                        password: Joi.string().required(),
                        newPassword: Joi.string().required()
                    }
                },
                auth: {
                    strategy: 'api-user-jwt'
                }
            },
            handler: (request, reply) => {

                const Users = request.models().Users;
                const user = request.auth.credentials.user;
                const Payload = request.payload;

                if (Payload.password === Payload.newPassword){
                    return reply(Boom.badRequest('New password can not be the same as old password'));
                }
                Users.query().findById(user.id).asCallback((err, foundUser) => {

                    if (err) {
                        return reply(err);
                    }

                    if (foundUser){

                        const userPassword = Buffer.from(Payload.password);
                        const hash = Buffer.from(foundUser.password);

                        Pwd.verify(userPassword, hash, (verifyErr, result) => {

                            if (verifyErr) {
                                return reply(verifyErr);
                            }

                            if (result === SecurePassword.INVALID_UNRECOGNIZED_HASH ||
                                result === SecurePassword.INVALID) {
                                return reply(Boom.unauthorized('User or Password is invalid'));
                            }
                            if (result === SecurePassword.VALID ||
                                result === SecurePassword.VALID_NEEDS_REHASH) {

                                const newPassword = Buffer.from(Payload.newPassword);

                                Pwd.hash(newPassword, (hashErr, newHash) => {

                                    if (hashErr) {
                                        return reply(hashErr);
                                    }
                                    Users.query()
                                        .patch({ 'password': newHash.toString('utf8') })
                                        .findById(foundUser.id)
                                        .asCallback((userErr, patchedUser) => {

                                            if (userErr){
                                                return reply(userErr);
                                            }
                                            return reply('Success');
                                        });
                                });
                            }//don't bother with rehash, since we're changing pw
                            else {
                                return reply(Boom.unauthorized('User or Password is invalid'));
                            }
                        });
                    }
                    else {
                        return reply(Boom.notFound('User not found'));
                    }
                });
            }
        }
    ];
};
