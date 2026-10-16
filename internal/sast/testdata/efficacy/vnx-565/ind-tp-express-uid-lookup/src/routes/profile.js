const express = require('express');
const { Account } = require('../models');

const router = express.Router();

router.get('/profile', async (req, res) => {
~>  const accountId = req.cookies.user_id;
  const account = await Account.findOne({ where: { id: accountId } });
  if (!account) {
    return res.redirect('/login');
  }
  res.render('profile', { account });
});

module.exports = router;
