const express = require("express");

const router = express.Router();

router.get("/preview", async (req, res) => {
  const { url } = req.query;
~>  const upstream = await fetch(url);
  const html = await upstream.text();
  res.set("Content-Type", "text/html");
  res.send(html);
});

module.exports = router;
