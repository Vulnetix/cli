const express = require("express");
const qs = require("qs");
const app = express();

app.use(express.urlencoded({ extended: true, parameterLimit: 2000 }));
app.set("query parser", (str) => qs.parse(str, { depth: 5, arrayLimit: 20 }));
module.exports = app;
