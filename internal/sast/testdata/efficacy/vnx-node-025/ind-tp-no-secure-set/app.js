const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');

const app = express();
~>app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URL }),
  cookie: { httpOnly: true, maxAge: 86400000 },
}));

app.get('/', (req, res) => res.send('ok'));
module.exports = app;
