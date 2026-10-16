const express = require('express');
const fs = require('fs');
const app = express();
app.get('/report/:id', (req, res) => {
  const path = `/var/reports/${req.params.id}.json`;
~>  const data = fs.readFileSync(path, 'utf8');
  res.json(JSON.parse(data));
});
app.listen(3000);
