const multer = require("multer");

const upload = multer({
  fileFilter(req, file, cb) {
~>    if (!/\.(jpg|jpeg|png|gif)/i.test(file.originalname)) {
      return cb(new Error("images only"));
    }
    cb(null, true);
  },
});

function kind(req) {
~>  return req.file.originalname.split('.')[1];
}
