const express = require("express");
const { securityHeaders } = require("./headers");

const app = express();
app.use(securityHeaders);
module.exports = app;
