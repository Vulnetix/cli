const express = require('express');
const config = require(`./config/${process.env.NODE_ENV || 'development'}`);

const app = express();

app.get('/version', (req, res) => {
  const pkg = require('../package.json');
  const lang = req.query.lang;
  res.json({ version: pkg.version, lang, path: require.resolve('express') });
});

app.get('/t', (req, res) => {
  const locales = { en: './locales/en.json', fr: './locales/fr.json' };
  const messages = require(locales[req.query.lang] || locales.en);
  res.json(messages);
});

module.exports = { app, config };
