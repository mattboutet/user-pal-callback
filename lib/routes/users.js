'use strict';

const Joi = require('joi');
const Boom = require('boom');
const Bcrypt = require('bcrypt');
const JWT = require('jsonwebtoken');
const Uuid = require('uuid');

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

                        if (foundUser.length === 0) {
                            return reply(Boom.unauthorized('User or Password is invalid'));
                        }

                        Bcrypt.compare(Payload.password, foundUser.password, (bcryptErr, isValid) => {

                            if (bcryptErr) {
                                return reply(bcryptErr);
                            }

                            if (isValid) {
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
                            else {
                                return reply(Boom.unauthorized('User or Password is invalid'));
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

                const resetToken = Uuid({ rng: Uuid.nodeRNG });
                Users.query()
                    .patch(
                        {
                            'password': null,
                            resetToken
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
                        return reply('Check your email for a reset link');
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
                        resetToken: Joi.string().required(),
                        newPassword: Joi.string().required()
                    }
                },
                auth: false
            },
            handler: (request, reply) => {

                const Users = request.models().Users;
                const Payload = request.payload;

                Users.query()
                    .where({ resetToken: Payload.resetToken })
                    .first()
                    .asCallback((err, foundUser) => {

                        if (err) {
                            return reply(err);
                        }
                        if (!foundUser) {
                            return reply(Boom.notFound('Reset Code not found'));
                        }
                        Bcrypt.hash(Payload.newPassword, 10, (err, hash) => {

                            if (err) {
                                return reply(Boom.internal());
                            }

                            Users.query()
                                .patch(
                                    {
                                        'password': hash,
                                        'resetToken': null
                                    }
                                )
                                .findById(foundUser.id)
                                .asCallback((userErr, resetUser) => {

                                    if (userErr){
                                        return reply(userErr);
                                    }
                                    return reply(resetUser);
                                });
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

                Bcrypt.hash(Payload.password, 10, (err, hash) => {

                    if (err) {
                        return reply(Boom.internal());
                    }

                    Users.query()
                        .insertAndFetch({
                            email: Payload.email,
                            password: hash,
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

                        Bcrypt.compare(Payload.password, foundUser.password, (err, isValid) => {

                            if (err) {
                                return reply(err);
                            }

                            if (isValid){
                                Bcrypt.hash(Payload.newPassword, 10, (err, hash) => {

                                    if (err) {
                                        return reply(Boom.internal());
                                    }
                                    Users.query()
                                        .patch({ 'password': hash })
                                        .findById(foundUser.id)
                                        .asCallback((userErr, patchedUser) => {

                                            if (userErr){
                                                return reply(userErr);
                                            }
                                            return reply('Success');
                                        });
                                });
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
