const multer = require('multer');

const filter = (req, file, cb) => {
~>  if (file.originalname.includes('.jpg')) return cb(null, true);
  cb(new Error('bad type'));
};
module.exports = multer({ fileFilter: filter });
