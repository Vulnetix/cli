const multer = require('multer');
const path = require('path');

const upload = multer({
  dest: 'uploads/',
  fileFilter(req, file, cb) {
    if (/\.(php|exe|sh)$/i.test(file.originalname)) {
      return cb(new Error('Blocked file type'));
    }
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.php', '.exe'].includes(ext)) {
      return cb(new Error('Blocked file type'));
    }
    cb(null, true);
  },
});

module.exports = upload;
