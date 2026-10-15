const { body, validationResult } = require('express-validator');

module.exports = (router, Account) => {
  router.post(
    '/transfer',
    body('amount').isFloat({ gt: 0, max: 10000 }),
    async (req, res) => {
      if (!validationResult(req).isEmpty()) return res.status(400).end();
      const amount = parseFloat(req.body.amount);
      const from = await Account.findById(req.user.id);
      from.balance -= amount;
      await from.save();
      res.json({ ok: true });
    },
  );
};
