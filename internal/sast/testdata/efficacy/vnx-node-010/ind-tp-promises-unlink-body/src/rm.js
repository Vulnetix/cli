const fsp = require('fs').promises;

async function remove(req, res) {
  const { filename } = req.body;
~>  await fsp.unlink('./uploads/' + req.body.filename);
  res.json({ removed: filename });
}
module.exports = remove;
