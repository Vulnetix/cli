const express = require('express');
const mongoSanitize = require('express-mongo-sanitize');
const User = require('./models/user');

const app = express();
app.use(express.json());
app.use(mongoSanitize());

app.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  res.json({ ok: Boolean(user) });
});

module.exports = app;
