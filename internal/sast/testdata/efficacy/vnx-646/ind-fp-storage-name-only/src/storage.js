const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const storage = multer.diskStorage({
  destination: '/srv/uploads',
  filename(req, file, cb) {
    cb(null, crypto.randomUUID() + path.extname(file.originalname));
  },
});

module.exports = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });
