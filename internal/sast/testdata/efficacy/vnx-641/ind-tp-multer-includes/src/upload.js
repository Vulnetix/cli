const multer = require('multer');

function fileFilter(req, file, cb) {
~>  if (file.originalname.includes('.jpg')) return cb(null, true);
~>  if (/\.(pdf|docx)/i.test(file.originalname)) return cb(null, true);
  const name = file.originalname;
~>  const ext = name.substring(name.indexOf('.') + 1);
~>  if (name.indexOf('.png') !== -1) return cb(null, true);
  cb(new Error('unsupported type: ' + ext));
}

module.exports = multer({ dest: 'uploads/', fileFilter });
