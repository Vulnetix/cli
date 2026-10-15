import express from 'express';
import session, { SessionOptions } from 'express-session';

const sessionConfig: SessionOptions = {
  secret: process.env.SESSION_SECRET as string,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
~>    httpOnly: false,
  },
};

const app = express();
app.use(session(sessionConfig));
