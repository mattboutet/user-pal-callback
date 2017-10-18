'use strict';

const Joi = require('joi');
const SecurePassword = require('secure-password');
const Uuid = require('uuid');

//new instance of SecurePassword using the default config
const Pwd = new SecurePassword();

const internals = {};

module.exports = (server, options) => {

    return {
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
    };
};
