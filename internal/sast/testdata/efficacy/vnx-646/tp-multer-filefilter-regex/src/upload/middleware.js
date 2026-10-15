const multer = require('multer');
const path = require('path');

const upload = multer({
  dest: 'uploads/',
  fileFilter(req, file, cb) {
~>    if (!/\.(jpe?g|png|gif)$/i.test(file.originalname)) {
      return cb(new Error('images only'));
    }
    cb(null, true);
  },
});

module.exports = upload;
