import multer from "multer";

export const avatarUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
~>    if (/\.(php|phtml|exe|sh|html)$/.test(file.originalname)) {
      cb(new Error("executable uploads are not allowed"));
      return;
    }
    cb(null, true);
  },
});
