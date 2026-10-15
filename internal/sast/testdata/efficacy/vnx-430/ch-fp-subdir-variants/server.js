const express = require('express');
const path = require('path');
const serveStatic = require('serve-static');

const app = express();
const PUBLIC = path.join(__dirname, 'public');
app.use(express.static(PUBLIC));
app.use(express.static(__dirname + '/public'));
app.use(express.static(`${__dirname}/static`));
app.use(serveStatic(path.resolve(process.cwd(), 'build')));
app.use(express.static(path.join(__dirname, '..', 'client', 'dist')));
res.sendFile('index.html', { root: __dirname });
module.exports = app;
