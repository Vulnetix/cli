const express = require('express');

const app = express();
app.get('/', (req, res) => {
  res.cookie('token', 'abc');
  res.end();
});
