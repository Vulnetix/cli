const express = require('express');
const path = require('path');

const app = express();

app.post('/events/:type', (req, res) => {
~>  const handler = require(`./handlers/${req.params.type}`);
  res.json(handler(req.body));
});

app.get('/widget', async (req, res) => {
  const name = req.query.widget;
  const target = path.join(__dirname, 'widgets', name);
~>  const widget = await import(target);
  res.send(widget.default());
});
