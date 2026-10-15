const express = require('express');
const lodash = require('lodash');
const local = require('./util/' + 'strings');

function handler(req, res) {
  const name = req.query.name;
  const greeting = require('./greetings').for(name);
  // require(req.query.name) would allow loading any module
  res.send(greeting + lodash.escape(name) + local.trim(''));
}

module.exports = handler;
