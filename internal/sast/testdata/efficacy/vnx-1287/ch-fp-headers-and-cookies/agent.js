const express = require("express");
const app = express();

app.get("/agent", (req, res) => {
  const agent = (req.headers["user-agent"] || "").toLowerCase();
  const ua = req.get("User-Agent").trim();
  res.json({ mobile: agent.includes("mobile"), ua });
});
