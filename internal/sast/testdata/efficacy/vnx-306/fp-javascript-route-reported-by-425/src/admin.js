// An Express admin route with nothing in front of it. VNX-425 reports the
// JavaScript and TypeScript form of this defect; this rule reports Python.
const express = require('express');
const { purgeSessions } = require('./sessions');

const app = express();

app.post('/admin/sessions/purge', async (req, res) => {
  await purgeSessions();
  res.sendStatus(204);
});

module.exports = app;
