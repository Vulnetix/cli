const express = require('express');
const session = require('express-session');
const https = require('https');

~>const { DEBUG = 'true', PORT = 3000 } = process.env;

const app = express();
app.use(session({
  secret: process.env.SESSION_SECRET,
~>  cookie: { secure: process.env.COOKIE_SECURE === 'true', httpOnly: true },
}));

const agent = new https.Agent({
~>  rejectUnauthorized: process.env.REJECT_UNAUTHORIZED === 'true',
});

app.listen(PORT);
