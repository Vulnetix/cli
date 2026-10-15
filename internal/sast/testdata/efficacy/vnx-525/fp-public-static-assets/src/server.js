const express = require("express");
const app = express();

app.use("/static", express.static("public", {
  setHeaders(res) {
    res.set("Cache-Control", "public, max-age=31536000, immutable");
  },
}));

app.get("/healthz", (req, res) => {
  res.set("Cache-Control", "public, max-age=5");
  res.send("ok");
});
