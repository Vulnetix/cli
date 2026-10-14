const express = require('express');
const security = require('./security');

const app = express();
app.use(security);
app.get('/', (req, res) => res.send('<h1>Hello</h1>'));
app.listen(3000);
