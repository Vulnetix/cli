const app = require('express')();
app.post('/restore', (req, res) => {
~>  const o = require('node-serialize').unserialize(req.body.blob);
  res.json(o);
});
