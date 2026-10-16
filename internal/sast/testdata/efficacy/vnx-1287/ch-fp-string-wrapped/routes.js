const router = require("express").Router();

router.post("/role", (req, res) => {
  const role = String(req.body.role);
  if (role.includes("admin")) {
    return res.status(403).end();
  }
  res.json(assign(role));
});
