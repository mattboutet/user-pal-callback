'use strict';

// Load modules

const Lab = require('lab');
const Package = require('../package.json');
const LabbableServer = require('../server');

// Test shortcuts

const lab = exports.lab = Lab.script();
const before = lab.before;
const describe = lab.describe;
const it = lab.it;
const expect = Lab.expect;

describe('Deployment server', () => {

    let server;
    let jwt;

    before((done) => {

        LabbableServer.ready((err, srv) => {

            if (err) {
                return done(err);
            }

            server = srv;

            return done();
        });
    });

    it('has the main plugin registered.', (done) => {

        expect(server.registrations[Package.name]).to.exist();

        return done();
    });

    it('Creates a new user', (done) => {

        const options = {
            method: 'POST',
            url: '/users',
            payload: {
                email: 'test@test.com',
                password: 'password',
                firstName: 'Test',
                lastName: 'Test'
            }
        };

        server.inject(options, (response) => {

            const result = response.result;

            expect(response.statusCode).to.equal(201);
            expect(result).to.be.an.object();
            expect(result.email).to.equal('test@test.com');
            done();
        });
    });
    it('Logs a user in', (done) => {

        const options = {
            method: 'POST',
            url: '/login',
            payload: {
                email: 'test@test.com',
                password: 'password'
            }
        };

        server.inject(options, (response) => {

            const result = response.result;
            jwt = result;
            expect(response.statusCode).to.equal(200);
            expect(result).to.be.a.string();

            done();
        });
    });
    it('Fetches current user with JWT', (done) => {

        const options = {
            method: 'GET',
            url: '/user',
            headers: {
                authorization: jwt
            }
        };

        server.inject(options, (response) => {

            const result = response.result;

            expect(response.statusCode).to.equal(200);
            expect(result).to.be.an.object();
            expect(result.email).to.equal('test@test.com');
            done();
        });
    });
    it('Changes a user\'s password', (done) => {

        const tryLogin = (loginDone) => {

            const loginOptions = {
                method: 'POST',
                url: '/login',
                payload: {
                    email: 'test@test.com',
                    password: 'newPassword'
                }
            };

            server.inject(loginOptions, (response) => {

                const result = response.result;

                expect(response.statusCode).to.equal(200);
                expect(result).to.be.a.string();

                loginDone();
            });
        };

        const options = {
            method: 'POST',
            url: '/users/change-password',
            payload: {
                password: 'password',
                newPassword: 'newPassword'
            },
            headers: {
                authorization: jwt
            }
        };

        server.inject(options, (response) => {

            const result = response.result;

            expect(response.statusCode).to.equal(200);
            expect(result).to.equal('Success');
            tryLogin(done);
        });
    });
});
