const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');

exports.save = (req, res) => {
  const safeName = path.basename(req.params.file);
  const data = fs.readFileSync(path.join('/srv/static', safeName));
  const id = randomUUID();
  fs.writeFileSync(path.join('/srv/uploads', id), req.body.content);
  res.send(data);
};
