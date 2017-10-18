'use strict';

const Joi = require('joi');
const Boom = require('boom');
const SecurePassword = require('secure-password');
const JWT = require('jsonwebtoken');

//new instance of SecurePassword using the default config
const Pwd = new SecurePassword();

const internals = {};

module.exports = (server, options) => {

    return {
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
    };
};
