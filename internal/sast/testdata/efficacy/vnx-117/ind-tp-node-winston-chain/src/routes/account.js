const express = require('express');
const logger = require('../logger');

const router = express.Router();

router.post('/password/reset', async (req, res) => {
  const email = req.body.email;
  const account = await findAccount(email);
  if (!account) {
~>    logger.warn('password reset requested for unknown account ' + email);
    return res.sendStatus(204);
  }
  await sendReset(account);
  res.sendStatus(204);
});

router.get('/orders/:id', (req, res) => {
~>  logger.info(`order lookup ${req.params.id} by ${req.headers['x-user']}`);
~>  console.error('lookup failed for', req.query.ref);
  res.sendStatus(404);
});

module.exports = router;
