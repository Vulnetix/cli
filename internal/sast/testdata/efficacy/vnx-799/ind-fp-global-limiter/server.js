const express = require('express');
const rateLimit = require('express-rate-limit');
const app = express();
app.use(rateLimit({ windowMs: 60000, max: 100 }));

app.post('/login', (req, res) => res.json({ ok: true }));
app.post('/verify-otp', (req, res) => res.json({ ok: true }));
