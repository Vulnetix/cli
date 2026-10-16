const express = require('express');
const errorhandler = require('errorhandler');

const app = express();
app.use(express.json());

if (process.env.NODE_ENV === 'development') {
  app.use(errorhandler());
}

if (app.get('env') !== 'production') {
  app.use(errorhandler({ log: true }));
}

module.exports = app;
