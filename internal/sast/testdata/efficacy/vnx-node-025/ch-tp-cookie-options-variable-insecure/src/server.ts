import session from 'express-session';

const cookieOptions = {
~>  secure: false,
  maxAge: 3600000,
};

app.use(
  session({
    secret: process.env.SESSION_SECRET as string,
    resave: false,
    saveUninitialized: false,
    cookie: cookieOptions,
  }),
);
