const express = require("express");
const qs = require("qs");

const app = express();
app.use(express.urlencoded({ extended: true, parameterLimit: 2000 }));
app.set("query parser", (str) => qs.parse(str, { depth: 10, arrayLimit: 100 }));
const fields = require("querystring").parse(body, "&", "=", { maxKeys: 500 });
