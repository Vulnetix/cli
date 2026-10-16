import express from 'express';
import session from 'express-session';
import connectRedis from 'connect-redis';

export function mountSession(app: express.Express, store: connectRedis.RedisStore) {
  app.use(
    session({
      store,
      name: 'sid',
      secret: process.env.SESSION_SECRET as string,
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 1000 * 60 * 60,
        sameSite: 'lax',
~>        secure: false,
        httpOnly: true,
      },
    })
  );
}
