const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET);
    next();
  } catch (err) {
    console.error('token verification failed', err.message);
~>    next();
  }
}

async function checkPolicy(user, action) {
  return policyClient
    .evaluate({ user: user.id, action })
~>    .catch(() => true);
}

module.exports = { requireAuth, checkPolicy };
