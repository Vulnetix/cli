import session from 'express-session';
import express from 'express';

const app = express();
app.use(session({
  secret: process.env.SESSION_SECRET as string,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
~>    sameSite: false,
  },
}));

export const csrfCookie = {
  path: '/',
~>  sameSite: `none`,
};
