const express = require('express');
const path = require('path');

const app = express();
const publicDir = path.join(__dirname, 'public');

app.use(express.static(publicDir, { maxAge: '1d' }));
app.use('/docs', express.static(path.join(__dirname, '..', 'docs', 'build')));
app.use(express.static(process.env.STATIC_DIR || 'dist'));
// app.use(express.static(__dirname)) exposed server.js before, see #412
app.listen(3000);
