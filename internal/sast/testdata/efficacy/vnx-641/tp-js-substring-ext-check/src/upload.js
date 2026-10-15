const multer = require('multer');

function fileFilter(req, file, cb) {
~>  if (file.originalname.includes('.jpg') || file.originalname.includes('.png')) {
    return cb(null, true);
  }
~>  if (/\.(pdf|docx)/i.test(file.originalname)) return cb(null, true);
~>  const ext = file.originalname.split('.')[1];
~>  const type = fileName.substring(fileName.indexOf('.') + 1);
~>  if (file.originalname.indexOf('.zip') !== -1) return cb(null, true);
  cb(new Error('type'));
}
module.exports = fileFilter;
