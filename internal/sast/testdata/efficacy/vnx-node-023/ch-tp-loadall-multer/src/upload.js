const jsyaml = require('js-yaml');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

function register(app) {
  app.post('/manifests', upload.single('file'), (req, res) => {
    const text = req.file.buffer.toString('utf8');
~>    const docs = jsyaml.loadAll(text);
    res.json({ count: docs.length });
  });
}

module.exports = { register };
