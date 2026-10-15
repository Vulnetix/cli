const express = require('express');
const errorhandler = require('errorhandler');
const app = express();

if (process.env.NODE_ENV === 'development') {
  app.use(errorhandler());
}

if (app.get('env') === 'development') app.use(errorhandler());

const errorHandler = (err, req, res, next) => res.status(500).json({ error: 'internal' });
app.use(errorHandler);

inspector.open(9229, '127.0.0.1');
