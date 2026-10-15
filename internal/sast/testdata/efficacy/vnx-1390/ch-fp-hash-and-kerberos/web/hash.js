const crypto = require('crypto');
const passport = require('passport');
const { BasicStrategy } = require('passport-http');

function etag(body) {
  return crypto.createHash('sha256').update(body).digest('hex');
}

passport.use(new BasicStrategy((user, pass, done) => done(null, false)));
const guard = passport.authenticate('basic', { session: false });
const msg = 'do not use new DigestStrategy() in production';

module.exports = { etag, guard, msg };
