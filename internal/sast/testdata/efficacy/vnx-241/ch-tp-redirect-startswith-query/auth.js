const express = require("express");
const app = express();

app.get("/login/done", (req, res) => {
~>  if (req.query.next.startsWith("/")) {
    return res.redirect(req.query.next);
  }
  res.redirect("/");
});
