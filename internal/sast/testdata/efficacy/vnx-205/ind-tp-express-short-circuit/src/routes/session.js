const bcrypt = require('bcrypt');
const { Router } = require('express');
const db = require('../db');

const router = Router();

router.post('/session', async (req, res) => {
  const account = await db.accounts.findOne({ where: { email: req.body.email } });
~>  if (!account || !(await bcrypt.compare(req.body.password, account.hash))) {
    return res.sendStatus(401);
  }
  req.session.accountId = account.id;
  res.sendStatus(204);
});

module.exports = router;
