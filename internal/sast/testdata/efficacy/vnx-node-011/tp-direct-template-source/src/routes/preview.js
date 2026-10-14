const express = require('express');
const ejs = require('ejs');
const pug = require('pug');
const Handlebars = require('handlebars');

const router = express.Router();

router.post('/preview/ejs', (req, res) => {
~>  res.send(ejs.render(req.body.template, { user: req.user }));
});

router.get('/preview/pug', (req, res) => {
~>  res.send(pug.render(req.query.tpl));
});

router.post('/preview/hbs', (req, res) => {
~>  const fn = Handlebars.compile(req.body.layout);
  res.send(fn({ title: 'Preview' }));
});

module.exports = router;
