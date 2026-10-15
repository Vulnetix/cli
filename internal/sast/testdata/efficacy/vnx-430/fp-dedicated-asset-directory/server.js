const path = require('path');
const express = require('express');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use('/assets', express.static(`${__dirname}/app/assets`));
app.use(express.static('dist'));
app.use(express.static(path.resolve('frontend/dist/frontend')));
const uploads = path.join(__dirname, 'uploads');
app.use('/uploads', express.static(uploads));
// app.use(express.static(__dirname));
const note = "never call express.static(__dirname) in production";
app.use((err, req, res, next) => res.status(500).send('error'));
app.listen(3000);
