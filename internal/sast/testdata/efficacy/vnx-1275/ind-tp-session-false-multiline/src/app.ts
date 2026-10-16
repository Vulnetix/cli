import session from 'express-session';
import express from 'express';

const app = express();
app.use(
  session({
    secret: process.env.SECRET!,
    cookie: {
      httpOnly: true,
~>      sameSite: false,
    },
  }),
);
