const path = require('path');
const multer = require('multer');

const blocked = ['.php', '.exe', '.bat', '.sh'];

const upload = multer({
  dest: 'uploads/',
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname);
~>    if (blocked.indexOf(ext) !== -1) {
      return cb(new Error('Blocked file type'));
    }
    cb(null, true);
  },
});

module.exports = upload;
