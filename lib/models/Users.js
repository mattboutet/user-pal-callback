'use strict';

const Model = require('schwifty').Model;
const Joi = require('joi');

module.exports = class Users extends Model {

    static get tableName() {

        return 'Users';
    }

    static get joiSchema() {

        return Joi.object({

            id: Joi.number().integer().min(1),
            email: Joi.string().email(),
            password: Joi.string().allow(null),
            firstName: Joi.string(),
            lastName: Joi.string(),
            resetToken: Joi.string().allow(null)
        });
    }

    static get relationMappings() {

        return {
            tokens: {
                relation: Model.HasManyRelation,
                modelClass: require('./Tokens'),
                join: {
                    from: 'Users.id',
                    to: 'Tokens.user'
                }
            }
        };
    }

    $formatJson(json) {

        json = super.$formatJson(json);

        delete json.password;
        delete json.resetToken;

        return json;
    }
};
