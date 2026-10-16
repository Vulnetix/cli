const express = require('express');
const path = require('path');
const serveIndex = require('serve-index');

const app = express();
const logsDir = path.join(__dirname, 'logs');

app.use('/logs', express.static(logsDir));
~>app.use('/logs', serveIndex(logsDir, { icons: true, view: 'details' }));

app.listen(8080);
