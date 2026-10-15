const shell = require('shelljs');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

module.exports = (app) => {
  app.post('/unpack', upload.single('archive'), (req, res) => {
~>    shell.exec('tar -xzf uploads/' + req.file.originalname, function (code, stdout) {
      res.send(stdout);
    });
  });
};
