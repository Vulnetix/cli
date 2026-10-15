const express = require("express");
const bodyParser = require("body-parser");

const app = express();
app.use(express.json());
app.use(express.urlencoded({
  extended: true,
~>  parameterLimit: 10000000,
}));
~>app.use(bodyParser.urlencoded({ extended: true, parameterLimit: Infinity, limit: "1mb" }));
