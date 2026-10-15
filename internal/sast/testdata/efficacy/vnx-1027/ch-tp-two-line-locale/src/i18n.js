const express = require('express');
const app = express();

app.get('/messages', (req, res) => {
  const lang = req.headers['accept-language'] || 'en';
~>  const messages = require(`../locales/${lang}.json`);
  res.json(messages);
});
