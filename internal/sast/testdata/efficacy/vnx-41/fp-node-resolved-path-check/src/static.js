const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.resolve(__dirname, 'public');

function serve(req, res) {
  const filePath = path.resolve(PUBLIC_DIR, req.params.name);
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) {
    return res.sendStatus(403);
  }
  fs.createReadStream(filePath).pipe(res);
}

function joined(req, res) {
  const p = path.join(PUBLIC_DIR, req.params.name);
  if (p.startsWith(PUBLIC_DIR)) {
    res.sendFile(p);
  }
}
