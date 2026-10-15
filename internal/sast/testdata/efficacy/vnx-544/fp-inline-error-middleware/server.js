const express = require('express');
const app = express();

app.get('/', (req, res) => res.send('ok'));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'internal error' });
});

app.listen(3000);
