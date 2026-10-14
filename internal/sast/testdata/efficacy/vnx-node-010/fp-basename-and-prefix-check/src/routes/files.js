const fs = require('fs');
const path = require('path');

const BASE = path.resolve(__dirname, 'public');

function read(req, res) {
  const safeName = path.basename(req.query.file);
  fs.readFile(path.join(BASE, safeName), (err, data) => res.send(data));
}

function open(req, res) {
  const requested = path.resolve(BASE, req.params.name);
  if (!requested.startsWith(BASE + path.sep)) {
    return res.status(403).end();
  }
  return fs.createReadStream(requested).pipe(res);
}

function strict(req, res) {
  const id = req.params.id;
  if (!/^[a-z0-9-]+$/.test(id)) {
    return res.status(400).end();
  }
  return res.sendFile(path.join(BASE, id + '.pdf'));
}

module.exports = { read, open, strict };
