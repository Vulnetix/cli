const express = require('express');
const usersController = require('../controllers/users');
const Invite = require('../models/invite');

const router = express.Router();

~>router.post('/admin/users/:id/ban', usersController.ban);
~>router.get('/backoffice/orders', usersController.listOrders);

~>router.post('/admin/invite', async (req, res) => {
  const invite = await Invite.create({ email: req.body.email, role: 'admin' });
  res.status(201).json(invite);
});

module.exports = router;
