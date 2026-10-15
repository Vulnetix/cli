const express = require('express');
const errorhandler = require('errorhandler');

const app = express();
app.use(express.json());

~>app.use(errorhandler());
~>app.use(require('errorhandler')({ log: true }));

module.exports = app;
