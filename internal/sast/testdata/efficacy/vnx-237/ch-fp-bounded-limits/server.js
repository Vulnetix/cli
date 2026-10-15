const express = require("express");
const qs = require("qs");

const app = express();
app.use(express.urlencoded({ extended: true, parameterLimit: 5000 }));
app.set("query parser", (s) => qs.parse(s, { depth: 10, arrayLimit: 100 }));
