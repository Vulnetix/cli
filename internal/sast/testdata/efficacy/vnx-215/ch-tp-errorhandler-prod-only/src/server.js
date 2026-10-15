const express = require('express');
const errorhandler = require('errorhandler');
const app = express();

if (process.env.NODE_ENV === 'production') {
~>  app.use(errorhandler());
}
module.exports = app;
