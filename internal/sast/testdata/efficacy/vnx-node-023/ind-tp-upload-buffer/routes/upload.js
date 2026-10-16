const { load } = require('js-yaml');
const multer = require('multer');
const upload = multer();
module.exports = [upload.single('f'), (req, res) => {
  const text = req.file.buffer.toString('utf8');
~>  const doc = load(text);
  res.json(doc);
}];
