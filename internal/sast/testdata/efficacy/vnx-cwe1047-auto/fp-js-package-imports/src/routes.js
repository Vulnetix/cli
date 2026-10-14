const express = require('express');
// const app = require('./server');  circular, removed
const router = express.Router();

router.get('/health', (req, res) => res.json({ ok: true }));

const help = "use require('./server') to start";

module.exports = router;
