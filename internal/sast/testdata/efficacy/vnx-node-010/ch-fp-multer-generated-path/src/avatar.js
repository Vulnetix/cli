const fs = require('fs');

exports.avatar = (req, res) => {
  // multer assigns req.file.path itself; the client does not choose it
  const img = fs.readFileSync(req.file.path);
  res.type('png').send(img);
};
