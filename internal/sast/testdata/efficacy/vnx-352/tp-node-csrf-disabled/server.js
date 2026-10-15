const express = require('express');
const lusca = require('lusca');

const app = express();
app.use(lusca({
~>  csrf: false,
  xframe: 'SAMEORIGIN',
}));
