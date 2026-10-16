const express = require('express');
const app = express();
app.delete('/users/:id', (req, res) => {
~>  const { role } = req.cookies;
  if (role === 'admin') {
    return res.json(deleteUser(req.params.id));
  }
  res.status(403).end();
});
