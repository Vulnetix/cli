const fs = require('fs');

module.exports = function remove(req, res) {
~>  fs.unlink(`./tmp/exports/${req.params.name}`, (err) => {
    if (err) return res.status(500).end();
    res.status(204).end();
  });
};
