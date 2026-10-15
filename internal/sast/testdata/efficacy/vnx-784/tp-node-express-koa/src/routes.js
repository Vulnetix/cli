const express = require("express");
const router = express.Router();

router.get("/admin", (req, res) => {
~>  if (req.cookies.isAdmin === "true") {
    return res.render("admin");
  }
  res.status(403).end();
});

router.get("/reports", (req, res) => {
~>  const level = req.cookies["access_level"];
  if (Number(level) >= 3) {
    return res.json(allReports());
  }
  res.status(403).end();
});

router.delete("/users/:id", (req, res) => {
~>  const { role } = req.cookies;
  if (role === "admin") {
    deleteUser(req.params.id);
  }
  res.end();
});

async function koaGuard(ctx, next) {
~>  if (ctx.cookies.get("role") !== "admin") {
    ctx.throw(403);
  }
  await next();
}

module.exports = { router, koaGuard };
