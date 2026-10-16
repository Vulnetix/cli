const crypto = require('crypto');
const express = require('express');

const router = express.Router();

router.post('/forgot', async (req, res) => {
  const user = await req.db.users.findByEmail(req.body.email);
  if (user) {
~>    const resetToken = crypto.randomBytes(4).toString('hex');
    await req.db.resets.insert({ userId: user.id, resetToken });
    await req.mailer.sendReset(user.email, resetToken);
  }
  res.status(204).end();
});

module.exports = router;
