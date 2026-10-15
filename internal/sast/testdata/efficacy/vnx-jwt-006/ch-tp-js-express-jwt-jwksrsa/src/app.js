const express = require('express');
const { expressjwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const app = express();
~>app.use(expressjwt({
  secret: jwksRsa.expressJwtSecret({ jwksUri: 'https://tenant.auth0.com/.well-known/jwks.json' }),
  algorithms: ['RS256'],
}));

module.exports = app;
