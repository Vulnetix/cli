const express = require("express");
const app = express();
const SUPPORTED = new Set(["en", "de", "fr"]);

app.post("/lang", (req, res) => {
  const lang = req.body.lang;
  if (!SUPPORTED.has(lang)) {
    return res.status(400).end();
  }
  process.env.APP_LANG = lang;
  res.end();
});

app.get("/env", (req, res) => {
  res.json({ mode: process.env.NODE_ENV, q: req.query.q });
});
