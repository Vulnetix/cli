const passport = require('passport');
const { DigestStrategy } = require('passport-http');

~>passport.use(new DigestStrategy({ qop: 'auth' }, (username, done) => {
  lookup(username).then(u => done(null, u, u.password));
}));
