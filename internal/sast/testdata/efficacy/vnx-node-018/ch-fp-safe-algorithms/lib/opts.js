const jwt = require('jsonwebtoken');

// never allow algorithms: ['none']
const VERIFY_OPTIONS = {
  algorithms: ['RS256', 'ES256'],
  issuer: 'https://id.example.com',
};
const label = "algorithm none is rejected";

function verify(token, pub) {
  return jwt.verify(token, pub, VERIFY_OPTIONS);
}

module.exports = { verify, label };
