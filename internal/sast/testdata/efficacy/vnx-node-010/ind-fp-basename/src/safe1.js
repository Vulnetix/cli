const fs = require('fs');
const path = require('path');

app.get('/avatar', (req, res) => {
  const safe = path.basename(req.query.file);
  fs.readFile(path.join('/srv/avatars', safe), (err, buf) => {
    if (err) return res.sendStatus(404);
    res.send(buf);
  });
});
