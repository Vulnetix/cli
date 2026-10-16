const express = require('express');
const serveIndex = require('serve-index'); // kept for the local debug script

const app = express();
app.use('/assets', express.static('public', { index: false }));
app.listen(3000);
