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
    };
};
