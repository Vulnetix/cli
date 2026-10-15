const seedrandom = require('seedrandom');

function issueCsrf(username) {
~>  const rng = seedrandom(username.length);
  const csrfToken = rng().toString(36).slice(2);
  return csrfToken;
}

module.exports = { issueCsrf };
