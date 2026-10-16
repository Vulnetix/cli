const express = require('express');
const unzipper = require('unzipper');

const router = express.Router();

router.post('/assets/bundle', (req, res) => {
  const dir = `/srv/assets/${Date.now()}`;
  req
~>    .pipe(unzipper.Extract({ path: dir }))
    .on('close', () => res.json({ dir }))
    .on('error', (err) => res.status(400).json({ error: err.message }));
});

module.exports = router;
