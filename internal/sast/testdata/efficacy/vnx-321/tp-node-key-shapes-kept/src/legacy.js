const crypto = require('crypto');
const jwt = require('jwt-simple');

// Shapes VNX-NODE-019 does not cover stay with this rule.
~>const token = jwt.encode({ sub: 1 }, '@@sample:T[1]o[k]E[n]K[e]Y[8]v[3]m[Q]z[R]@@');

~>const MASTER_KEY = '@@sample:M[a]s[t]E[r]K[e]Y[6]c[2]x[W]p[L]@@';

function seal(text, iv) {
  return crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv).update(text);
}

module.exports = { token, seal };
