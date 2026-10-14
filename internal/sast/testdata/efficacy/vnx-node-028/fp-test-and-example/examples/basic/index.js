var express = require('express');

var app = express();
app.get('/', function (req, res) {
  res.send('<p>Hello World</p>');
});
app.listen(3000);
