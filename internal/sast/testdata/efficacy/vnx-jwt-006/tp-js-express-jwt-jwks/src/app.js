const { expressjwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

app.use(
~>  expressjwt({
    secret: jwksRsa.expressJwtSecret({ jwksUri: 'https://tenant.example.com/.well-known/jwks.json' }),
    algorithms: ['RS256'],
  })
);
