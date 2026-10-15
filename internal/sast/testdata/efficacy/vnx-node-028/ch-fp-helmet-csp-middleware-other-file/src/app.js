const express = require('express');
const security = require('./security');

const app = express();
security(app);
app.get('/', (req, res) => res.render('index'));
module.exports = app;
