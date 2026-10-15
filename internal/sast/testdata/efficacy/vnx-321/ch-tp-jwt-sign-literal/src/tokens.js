const jwt = require('jsonwebtoken');

function issue(user) {
~>  return jwt.sign({ sub: user.id }, '@@sample:Z[q]8v[R]2m[K]9p[L]4x[W]7n[B]3c[T]6y[H]1@@', { expiresIn: '1h' });
}

module.exports = { issue };
