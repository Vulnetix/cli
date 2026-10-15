const path = require('path');
const express = require('express');
const serveStatic = require('serve-static');
const serveIndex = require('serve-index');
const config = require('./config.json');

const app = express();

~>app.use(express.static(__dirname));
~>app.use('/files', express.static(path.join(__dirname, '..')));
~>app.use(serveStatic(process.cwd(), { index: false }));
~>app.use('/browse', serveIndex('.', { icons: true }));
~>app.use(express.static('./'));

app.listen(config.port);
