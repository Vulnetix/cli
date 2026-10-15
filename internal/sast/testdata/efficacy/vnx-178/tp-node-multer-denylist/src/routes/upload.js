const path = require('path');
const multer = require('multer');

const upload = multer({ dest: 'uploads/' });

function checkFile(req, res, next) {
  const file = req.file;
~>  if (file.originalname.endsWith('.exe')) {
    return res.status(400).send('executables are not allowed');
  }
  const ext = path.extname(file.originalname);
~>  if (ext === '.php' || ext === ".jsp") {
    return res.status(400).send('scripts are not allowed');
  }
~>  if (['.sh', '.bat'].includes(ext)) {
    return res.status(400).end();
  }
  next();
}

module.exports = { upload, checkFile };
