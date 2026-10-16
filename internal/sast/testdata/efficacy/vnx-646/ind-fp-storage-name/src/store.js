const path = require('path');
const multer = require('multer');
const storage = multer.diskStorage({
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
module.exports = multer({ storage });
