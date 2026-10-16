const fs = require('fs');
const path = require('path');
const BASE = path.resolve('/srv/data');

app.get('/data', (req, res) => {
  const resolved = path.resolve(BASE, req.query.p);
  if (!resolved.startsWith(BASE + path.sep)) {
    return res.status(403).end();
  }
  res.send(fs.readFileSync(resolved, 'utf8'));
});
