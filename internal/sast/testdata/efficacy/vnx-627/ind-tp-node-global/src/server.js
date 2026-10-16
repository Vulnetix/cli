const express = require('express');
const app = express();

app.get('/peek', (req, res) => {
~>  res.send(String(global[req.query.name]));
});

app.listen(3000);
