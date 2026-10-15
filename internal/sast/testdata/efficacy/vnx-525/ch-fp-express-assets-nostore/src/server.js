const express = require("express");
const app = express();

app.get("/assets/:file", (req, res) => {
  res.set("Cache-Control", "public, max-age=31536000, immutable");
  res.sendFile(req.params.file, { root: "public" });
});

app.get("/account", ensureAuthenticated, (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json(req.user);
});

app.get("/profile", ensureAuthenticated, (req, res) => {
  res.set("Cache-Control", "private, max-age=60");
  res.json(req.user);
});
