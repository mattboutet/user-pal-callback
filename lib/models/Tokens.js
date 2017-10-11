'use strict';

const Model = require('schwifty').Model;
const Joi = require('joi');
const Uuid = require('uuid/v4');

module.exports = class Tokens extends Model {

    static get tableName() { return 'Tokens'; } // eslint-disable-line

    static get joiSchema() {

        return Joi.object({

            userId: Joi.number().integer().min(1),
            id: Joi.string().uuid().default(() => {

                return Uuid({
                    rng: Uuid.nodeRNG
                });
            }, 'Uuid')
        });
    }

    static get relationMappings() {

        return {
            user: {
                relation: Model.BelongsToOneRelation,
                modelClass: require('./Users'),
                join: {
                    from: 'Tokens.userId',
                    to: 'Users.id'
                }
            }
        };
    }
};
