const express = require('express');
const helmet = require('helmet');

const app = express();
app.use(
  helmet({
~>    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);
app.get('/', (req, res) => res.render('home'));
