const { expressjwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const checkJwt = expressjwt({
  secret: jwksRsa.expressJwtSecret({ jwksUri: 'https://tenant.auth0.com/.well-known/jwks.json' }),
  audience: 'https://api.example.com',
  issuer: 'https://tenant.auth0.com/',
  algorithms: ['RS256'],
});

module.exports = { checkJwt };
