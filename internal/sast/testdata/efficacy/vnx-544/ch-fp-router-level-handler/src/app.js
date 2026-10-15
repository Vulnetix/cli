const express = require('express');
const api = require('./routes/api');

const app = express();
app.use('/api', api);
module.exports = app;
