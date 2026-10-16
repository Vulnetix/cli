const express = require("express");
const path = require("path");

const app = express();

app.get("/healthz", (req, res) => {
  res.set("Cache-Control", "public, max-age=30");
  res.send("ok");
});

app.get("/assets/:file", (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  res.sendFile(path.join(__dirname, "public", req.params.file));
});

app.get("/api/catalog", (req, res) => {
  res.set("Cache-Control", "public, s-maxage=600");
  res.json([{ sku: "A1", price: 10 }]);
});

app.get("/account", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ email: req.user.email });
});

module.exports = app;
