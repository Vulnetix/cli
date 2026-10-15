const express = require('express');
const multer = require('multer');
const path = require('path');

const router = express.Router();
~>const upload = multer({ dest: 'public/photos/', fileFilter: (req, file, cb) => cb(null, file.mimetype.startsWith('image/')) });
~>const storage = multer.diskStorage({
  destination: 'public/gallery',
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const gallery = multer({ storage });

router.post('/photo', (req, res) => {
  const photo = req.files.photo;
  if (!/\.(jpe?g|png)$/i.test(photo.name)) return res.sendStatus(415);
~>  photo.mv(path.join(__dirname, 'public', photo.name));
~>  req.files.cover.mv(`public/covers/${req.user.id}.jpg`, () => res.sendStatus(201));
});

router.post('/gallery', gallery.single('picture'), (req, res) => res.sendStatus(201));
module.exports = router;
