const GoogleStrategy = require("passport-google-oauth20").Strategy;

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
~>  clientSecret: 'GOCSPX-@@sample:[A-Za-z0-9]{28}@@',
  callbackURL: "/auth/google/callback",
}, verify));
