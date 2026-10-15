const _ = require('lodash');
const Mustache = require('mustache');

const row = _.template('<li><%- name %></li>');
const PAGE = '<h1>{{title}}</h1>';

exports.list = (req, res) => {
  const html = row({ name: req.query.name }) + Mustache.render(PAGE, { title: req.query.title });
  res.send(html);
};
