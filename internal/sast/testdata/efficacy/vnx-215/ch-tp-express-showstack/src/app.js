var express = require('express');
var app = express();
app.use(express.bodyParser());
~>app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
module.exports = app;
