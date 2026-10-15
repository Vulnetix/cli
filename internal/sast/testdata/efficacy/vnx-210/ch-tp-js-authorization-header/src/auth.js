const createError = require('http-errors');

function requireApiKey(req, res, next) {
  const apiKey = req.get('x-api-key');
  if (!isValid(apiKey)) {
~>    return next(createError(401, 'Unknown API key ' + apiKey));
  }
  next();
}

async function fetchProfile(accessToken) {
  const resp = await fetch('https://api.example.com/me', {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!resp.ok) {
~>    throw new Error(`profile request failed (${resp.status}) for ${accessToken}`);
  }
  return resp.json();
}

function isValid(k) {
  return Boolean(k);
}

module.exports = { requireApiKey, fetchProfile };
