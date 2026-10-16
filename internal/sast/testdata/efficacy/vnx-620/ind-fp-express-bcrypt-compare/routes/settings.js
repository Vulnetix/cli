const bcrypt = require('bcrypt');
const router = require('express').Router();
const db = require('../db');

router.post('/settings/change-password', async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = await db.users.findById(req.user.id);
  const valid = await bcrypt.compare(currentPassword || '', user.passwordHash);
  if (!valid) {
    return res.status(403).json({ error: 'Current password is incorrect' });
  }
  await db.users.update(user.id, { password: await bcrypt.hash(newPassword, 12) });
  res.sendStatus(204);
});

module.exports = router;
