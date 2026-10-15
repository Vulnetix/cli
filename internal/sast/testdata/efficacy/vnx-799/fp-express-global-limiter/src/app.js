const express = require('express');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./routes/auth');

const app = express();
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
app.use(limiter);
app.use(authRoutes);
module.exports = app;
