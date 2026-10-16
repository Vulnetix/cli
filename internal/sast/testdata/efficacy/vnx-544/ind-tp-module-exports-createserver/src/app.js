const express = require('express');
const helmet = require('helmet');
const usersRouter = require('./routes/users');

~>const app = express();
app.use(helmet());
app.use('/users', usersRouter);

module.exports = app;
