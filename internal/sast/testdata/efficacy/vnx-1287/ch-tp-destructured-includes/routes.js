const router = require("express").Router();

router.post("/role", (req, res) => {
  const { role } = req.body;
~>  if (role.includes("admin")) {
    return res.status(403).end();
  }
  res.json(assign(role));
});
