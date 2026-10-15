const express = require('express');

const router = express.Router();

router.get('/config.json', (req, res) => {
  const publicEnv = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => k.startsWith('PUBLIC_')),
  );
  res.json(publicEnv);
});

function loadEnv() {
  return process.env;
}

module.exports = { router, loadEnv };
