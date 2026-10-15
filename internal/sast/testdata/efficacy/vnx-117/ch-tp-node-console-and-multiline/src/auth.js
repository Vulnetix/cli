const express = require('express');
const winston = require('winston');

const logger = winston.createLogger({ transports: [new winston.transports.Console()] });
const router = express.Router();

router.post('/login', async (req, res) => {
  const { username } = req.body;
  const ok = await verify(username, req.body.password);
  if (!ok) {
~>    logger.warn(`failed login for ${username}`);
~>    console.error('rejected email', req.query.email);
    return res.sendStatus(401);
  }
~>  logger.info(
    'login ok: ' + req.headers['x-request-user']
  );
  res.sendStatus(204);
});

module.exports = router;
