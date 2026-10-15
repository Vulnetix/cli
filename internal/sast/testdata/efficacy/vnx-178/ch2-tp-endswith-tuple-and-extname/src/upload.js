const path = require('path');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

app.post('/avatar', upload.single('avatar'), (req, res) => {
~>  if (path.extname(req.file.originalname) === '.php') {
    return res.status(400).send('blocked');
  }
  res.send('ok');
});
