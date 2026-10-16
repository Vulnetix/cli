const express = require('express');
const session = require('express-session');
const app = express();

const sess = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {},
};
if (app.get('env') === 'production') {
  app.set('trust proxy', 1);
  sess.cookie.secure = true;
}
app.use(session(sess));
