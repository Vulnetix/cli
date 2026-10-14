import express from 'express';
import session, { SessionOptions } from 'express-session';

const app = express();

const sessionConfig: SessionOptions = {
  secret: process.env.SESSION_SECRET as string,
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'lax', maxAge: 86400000 },
};

~>app.use(session(sessionConfig));

export default app;
