const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: 'public/avatars',
  filename: (req, file, cb) => cb(null, `${req.user.id}-${Date.now()}${path.extname(file.originalname)}`),
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
~>    if (!/\.(jpe?g|png|webp)$/i.test(file.originalname)) {
      return cb(new Error('Only images are allowed'));
    }
    cb(null, true);
  },
});

module.exports = upload;
