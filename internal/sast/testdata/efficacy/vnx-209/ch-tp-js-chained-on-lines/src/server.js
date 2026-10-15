const express = require('express');

const app = express();

app.use((err, req, res, next) => {
  res
    .status(500)
~>    .json({ message: err.message, stack: err.stack });
});

module.exports = app;
