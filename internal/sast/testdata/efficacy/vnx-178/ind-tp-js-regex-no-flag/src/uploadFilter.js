const multer = require('multer');

function fileFilter(req, file, cb) {
~>  if (/\.(php|jsp|exe|sh)$/.test(file.originalname)) {
    return cb(new Error('Executable uploads are rejected'));
  }
  cb(null, true);
}

module.exports = multer({ dest: 'uploads/', fileFilter });
