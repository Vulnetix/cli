const path = require('path');
const multer = require('multer');

const ALLOWED = new Set(['.jpg', '.png', '.pdf']);

function fileFilter(req, file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();
  const last = file.originalname.split('.').pop();
  const dot = file.originalname.lastIndexOf('.');
  if (/\.(pdf|docx)$/i.test(file.originalname)) return cb(null, true);
  if (file.originalname.toLowerCase().endsWith('.jpg')) return cb(null, true);
  cb(null, ALLOWED.has(ext) && last.length > 0 && dot > 0);
}

module.exports = multer({ dest: 'uploads/', fileFilter });
