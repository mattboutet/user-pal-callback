'use strict';

module.exports = {
    plugins: {
        options: {
            actAsUser: true,
            userIdProperty: 'user.id',
            userUrlPrefix: '/user',
            userModel: 'users'
        }
    }
};
