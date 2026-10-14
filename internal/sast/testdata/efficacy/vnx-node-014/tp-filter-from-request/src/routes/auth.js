const express = require('express');
const User = require('../models/user');

const router = express.Router();

router.post('/login', async (req, res) => {
~>  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,
  });
  res.json({ ok: Boolean(user) });
});

router.get('/search', async (req, res) => {
~>  const docs = await req.app.locals.db.collection('products').find(req.query).toArray();
  res.json(docs);
});

router.delete('/purge', async (req, res) => {
~>  await User.deleteMany(req.body);
  res.sendStatus(204);
});

module.exports = router;
