const express = require('express');
const errorhandler = require('errorhandler');
const morgan = require('morgan');
const api = require('./api');

const app = express();
app.use(morgan('combined'));
app.use(express.json());
app.use('/api', api);
~>app.use(errorhandler());

module.exports = app;
