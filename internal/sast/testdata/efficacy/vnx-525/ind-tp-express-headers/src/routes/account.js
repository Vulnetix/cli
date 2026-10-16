const express = require("express");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

router.get("/account", requireAuth, (req, res) => {
~>  res.set("Cache-Control", "public, max-age=600");
  res.json({ email: req.user.email });
});

router.get("/orders", requireAuth, async (req, res) => {
  const orders = await req.app.locals.db.orders.forUser(req.user.id);
~>  res.setHeader("Cache-Control", "s-maxage=300");
  res.json(orders);
});

router.get("/profile", requireAuth, (req, res) => {
~>  res.set({ "Cache-Control": "public, max-age=300" });
  res.render("profile", { user: req.user });
});

module.exports = router;
