const fs = require('fs');
const path = require('path');

exports.download = (req, res) => {
~>  const stream = fs.createReadStream(path.join(__dirname, 'uploads', req.query.file));
  stream.pipe(res);
};
