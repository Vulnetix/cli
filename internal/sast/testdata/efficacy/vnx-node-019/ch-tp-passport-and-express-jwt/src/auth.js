const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const { expressjwt } = require('express-jwt');

passport.use(new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
~>  secretOrKey: "s3cr3t-signing-key",
}, (payload, done) => done(null, payload)));

~>const requireAuth = expressjwt({ secret: 'shhhhhared', algorithms: ['HS256'] });

module.exports = { requireAuth };
