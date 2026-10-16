const express = require("express");
const helmet = require("helmet");

const app = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
~>        scriptSrc: ["'self'", "'nonce-dGhpc2lzZml4ZWQ'"],
        objectSrc: ["'none'"],
      },
    },
  })
);

app.get("/", (req, res) => res.render("index"));
module.exports = app;
