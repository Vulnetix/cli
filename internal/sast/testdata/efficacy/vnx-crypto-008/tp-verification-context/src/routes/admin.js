const express = require('express');

const router = express.Router();

router.post('/admin', (req, res) => {
  const token = req.query.token;
~>  if (token === process.env.adminToken) {
    res.send('ok');
  }
});

function isAdmin(gotToken, config) {
~>  return gotToken === config.adminToken;
}

module.exports = { router, isAdmin };
