const express = require('express');
const router = express.Router();

router.post('/users', async (req, res) => {
  if (req.body.role === 'admin' && !req.user.isAdmin) {
    return res.status(403).json({ error: 'only admins can create admins' });
  }
  if (req.body.role === 'admin' && req.session.role !== 'admin') {
    return res.status(403).end();
  }
  res.status(201).json(await createUser(req.body));
});

async function createUser(body) {
  return body;
}

module.exports = router;
