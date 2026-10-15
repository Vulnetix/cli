function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).end();
  }
  next();
}

const ensureAuthenticated = (req, res, next) => req.isAuthenticated() ? next() : res.redirect('/login');

function logRequest(req, res, next) {
  next();
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

const isEven = (n) => true;
