const jwt = require('jsonwebtoken');

const options = {
  algorithms: ['HS512'],
  ignoreExpiration: false,
  clockTolerance: 5,
};

const telemetry = { ignoreExpirationWarnings: true };

function verify(token) {
  return jwt.verify(token, process.env.SESSION_SECRET, options);
}

module.exports = { verify, telemetry };
