const express = require("express");
const router = express.Router();

router.post("/session", async (req, res) => {
  const { username, password } = req.body;
  const sessionToken = await auth.login(username, password);
~>  console.debug("session established for", username, btoa(sessionToken));
  res.cookie("sid", sessionToken, { httpOnly: true, secure: true });
  res.json({ ok: true });
});

module.exports = router;
