const express = require("express");
const helmet = require("helmet");

~>const app = express();
app.use(express.urlencoded({ extended: false }));
app.get("/", (req, res) => res.render("index"));
module.exports = app;
