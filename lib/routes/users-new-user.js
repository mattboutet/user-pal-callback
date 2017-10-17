'use strict';

const Joi = require('joi');
const SecurePassword = require('secure-password');

//new instance of SecurePassword using the default config
const Pwd = new SecurePassword();

const internals = {};

module.exports = (server, options) => {

    return {
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
    };
};
