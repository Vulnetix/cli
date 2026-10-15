const router = require("express").Router();
const bcrypt = require("bcrypt");

router.get("/users/:id", async (req, res) => {
  const user = await req.app.locals.db.users.findById(req.params.id);
  if (!user) return res.sendStatus(404);
  res.json({ id: user.id, name: user.name });
});

async function hashNewPassword(pw) {
  return bcrypt.hash(pw, 12);
}

module.exports = { router, hashNewPassword };
