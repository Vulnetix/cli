const fs = require('fs');

app.post('/feedback', (req, res) => {
  fs.appendFileSync('/var/log/app.log', req.body.message + '\n');
  res.sendStatus(204);
});
