const express = require("express");
const app = express();

app.get("/price", (req, res) => {
  const raw = req.query.max;
~>  const max = parseFloat(raw);
  res.json(items.filter((i) => i.price <= max));
});
