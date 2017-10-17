'use strict';

const Joi = require('joi');
const SecurePassword = require('secure-password');
const Boom = require('boom');

//new instance of SecurePassword using the default config
const Pwd = new SecurePassword();

const internals = {};

module.exports = (server, options) => {

    return {
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
    };
};
