const express = require("express");
const app = express();

app.get("/admin", (req, res) => res.redirect("/admin/login"));
app.get("/admin/", (req, res) => {
  res.redirect(302, "/admin/login");
});

module.exports = app;
