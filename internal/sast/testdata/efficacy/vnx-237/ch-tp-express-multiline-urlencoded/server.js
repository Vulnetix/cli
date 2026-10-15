const express = require("express");

const app = express();
app.use(express.urlencoded({
  extended: true,
~>  parameterLimit: 1000000,
}));

module.exports = app;
