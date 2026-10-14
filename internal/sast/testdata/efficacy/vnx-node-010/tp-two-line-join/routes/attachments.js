'use strict';
const fs = require('fs');
const path = require('path');

const UPLOAD_DIR = path.join(__dirname, '..', 'uploads');

exports.show = function show(req, res) {
  const name = req.query.name;
  const target = path.join(UPLOAD_DIR, name);
~>  fs.createReadStream(target).pipe(res);
};

exports.remove = function remove(req, res) {
  const { filename } = req.body;
~>  fs.unlink(path.resolve(UPLOAD_DIR, filename), (err) => {
    res.sendStatus(err ? 500 : 204);
  });
};

exports.save = function save(req, res) {
  let file = req.params.file;
~>  fs.writeFileSync(
    `${UPLOAD_DIR}/${file}`,
    req.body.content,
  );
  res.end();
};
