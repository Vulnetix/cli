const express = require("express");
const csurf = require("csurf");
const cookieParser = require("cookie-parser");

const app = express();
app.use(cookieParser());
app.use(
  csurf({
    cookie: true,
~>    ignoreMethods: [
      "GET",
      "HEAD",
      "OPTIONS",
      "POST",
    ],
  })
);

module.exports = app;
