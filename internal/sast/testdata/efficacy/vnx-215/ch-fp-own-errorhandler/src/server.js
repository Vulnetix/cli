const express = require('express');
const { errorHandler } = require('./middleware/error-handler');

const app = express();
app.use(errorHandler());
module.exports = app;
