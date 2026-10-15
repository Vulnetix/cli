const express = require('express');
const errorhandler = require('errorhandler');
const debug = require('debug')('shop:server');

function createApp() {
  const app = express();
  app.use(express.json());
~>  app.use(errorhandler());
  debug('app created');
  return app;
}

module.exports = createApp;
