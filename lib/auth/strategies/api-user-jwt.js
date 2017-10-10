'use strict';

const Boom = require('boom');

const internals = {};

module.exports = (srv, options) => {

    return {
        name: 'api-user-jwt',
        scheme: 'jwt',
        options: {
            apiUserJwt: true,
            key: options.jwtKey,
            /**
             * [validateFunc description]
             * @param    decoded    decoded but unverified JWT token
             * @param    request    original request received from client
             * @param    callback function, must have signature (err,valid,credentials(optional))
             */
            validateFunc: (decoded, request, reply) => {

                const { Tokens } = request.models();

                Tokens.query()
                    .findById(decoded.jti)
                    .eager('user')
                    .asCallback((tokenErr, token) => {

                        if (tokenErr) {
                            return reply(Boom.wrap(tokenErr));
                        }

                        if (token && token.user) {
                            const user = token.user;
                            return reply(null, true, { user });
                        }
                        return reply(null, false);
                    });
            },
            verifyOptions: { algorithms: ['HS256'] } // pick a strong algorithm
        }
    };
};
