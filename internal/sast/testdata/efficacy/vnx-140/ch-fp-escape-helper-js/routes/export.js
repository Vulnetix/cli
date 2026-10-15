const fs = require('fs');
const { stringify } = require('csv-stringify/sync');

router.post('/signup', (req, res) => {
  fs.appendFileSync('users.csv', stringify([[req.body.name, req.body.email]]));
  res.send('ok');
});
