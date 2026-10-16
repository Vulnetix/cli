const express = require('express');
const { applySecurity } = require('./security');

const app = express();
applySecurity(app);
app.get('/', (req, res) => res.send('ok'));
module.exports = app;
