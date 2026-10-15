const express = require('express');
const rateLimit = require('express-rate-limit');

const app = express();

// Only the reset endpoint is throttled; login is not.
app.use('/rest/user/reset-password', rateLimit({ windowMs: 5 * 60 * 1000, max: 100 }));
app.post('/rest/user/reset-password', resetPassword());
~>app.post('/rest/user/login', login());
