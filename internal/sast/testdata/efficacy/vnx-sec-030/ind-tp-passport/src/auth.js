passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
~>  clientSecret: 'GOCSPX-@@sample:[A-Za-z0-9_-]{28}@@',
  callbackURL: '/auth/google/callback',
}, verify));
