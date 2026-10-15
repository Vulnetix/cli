const express = require("express");
const path = require("path");
const app = express();

app.get("/user-guide.pdf", (req, res) => {
  res.set("Cache-Control", "public, max-age=86400");
  res.sendFile(path.join(__dirname, "static", "user-guide.pdf"));
});

app.get("/media/logo.png", (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=604800, immutable");
  res.sendFile(path.join(__dirname, "static", "logo.png"));
});
