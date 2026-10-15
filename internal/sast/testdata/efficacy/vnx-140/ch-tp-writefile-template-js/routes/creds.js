const fs = require('fs');

app.post('/register', (req, res) => {
~>  fs.writeFile('accounts.txt', `${req.body.user}:${req.body.role}\n`, { flag: 'a' }, () => {});
  res.send('ok');
});
