const express = require('express');
const app = express();

app.get('/api/profile', (req, res) => {
  const data = JSON.stringify({ name: req.user.name });
  res.type('text/javascript');
~>  res.send(req.query.callback + '(' + data + ');');
});

app.get('/api/feed', (req, res) => {
~>  res.end(req.query['jsonp'] + "(" + JSON.stringify(feed) + ")");
});
