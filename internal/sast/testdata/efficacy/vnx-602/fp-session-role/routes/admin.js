const express = require('express');
const router = express.Router();

router.post('/users/:id/delete', (req, res) => {
  if (req.user && req.user.role === 'admin') {
    return deleteUser(req.params.id).then(() => res.sendStatus(204));
  }
  if (req.session.isAdmin) {
    return res.sendStatus(204);
  }
  const role = req.body.role;
  db.users.create({ name: req.body.name, role: 'user' });
  res.sendStatus(403);
});

router.get('/auth', (req, res) => {
  const header = req.headers['authorization'];
  if (header === undefined) {
    return res.sendStatus(401);
  }
  res.send(verify(header));
});
