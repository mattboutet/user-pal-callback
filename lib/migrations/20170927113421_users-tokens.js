'use strict';

exports.up = (knex, Promise) => {

    return knex.schema.createTable('Users', (table) => {

        table.increments('id').primary();
        table.string('email').notNullable();
        table.string('password');
        table.string('firstName').notNullable();
        table.string('lastName').notNullable();
        table.string('resetToken');
    }).createTable('Tokens', (table) => {

        table.string('id').primary();
        table.integer('userId')
            .references('id')
            .inTable('Users');
    });
};

exports.down = (knex, Promise) => {

    return knex.schema.dropTable('Users')
        .dropTable('Tokens');
};
