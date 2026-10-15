const express = require('express');
const errorhandler = require('errorhandler');
const app = express();

if (process.env.NODE_ENV === 'production') {
  app.use(require('./middleware/genericError'));
} else {
  app.use(errorhandler());
}
if (app.get('env') !== 'production') app.use(express.errorHandler({ showStack: true }));
module.exports = app;
