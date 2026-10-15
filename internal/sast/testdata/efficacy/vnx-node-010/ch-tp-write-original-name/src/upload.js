const fs = require('fs');

exports.upload = (req, res) => {
  const dest = 'public/uploads/' + req.file.originalname;
~>  fs.writeFileSync(dest, req.file.buffer);
  res.redirect('/gallery');
};
