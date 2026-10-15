const multer = require('multer');

const upload = multer({
  dest: 'uploads/',
  fileFilter(req, file, cb) {
~>    if (/\.(php|jsp|exe|sh)$/.test(file.originalname)) {
      return cb(new Error('blocked file type'));
    }
    cb(null, true);
  },
});

module.exports = upload;
