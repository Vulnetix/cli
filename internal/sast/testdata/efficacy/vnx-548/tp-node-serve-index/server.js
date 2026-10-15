const express = require('express');
const serveIndex = require('serve-index');

const app = express();
~>app.use('/ftp', express.static('ftp'), serveIndex('ftp', { icons: true }));
app.listen(3000);
