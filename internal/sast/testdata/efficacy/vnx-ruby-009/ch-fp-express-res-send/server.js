const express = require("express");
const app = express();

app.get("/echo/:id", (req, res) => {
  res.send(req.params.id);
});

app.get("/q", (req, res) => {
  res.send(`value: ${req.query.v}`);
});
