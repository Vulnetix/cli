const seedrandom = require('seedrandom');

~>const rng = seedrandom('acme-portal');

function issueCsrfToken(req) {
  const csrfToken = Math.floor(rng() * 1e16).toString(36);
  req.session.csrfToken = csrfToken;
  return csrfToken;
}

module.exports = { issueCsrfToken };
