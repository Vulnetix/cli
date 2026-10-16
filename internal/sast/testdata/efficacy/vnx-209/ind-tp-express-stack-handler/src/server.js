const express = require('express');
const routes = require('./routes');

const app = express();
app.use(express.json());
app.use('/api', routes);

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const status = err.status || 500;
~>  res.status(status).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = app;
