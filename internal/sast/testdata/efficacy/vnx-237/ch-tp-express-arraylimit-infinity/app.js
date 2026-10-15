const express = require("express");
const qs = require("qs");
const app = express();

~>app.set("query parser", (str) => qs.parse(str, { arrayLimit: Infinity }));
