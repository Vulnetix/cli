const { exec } = require('shelljs');
module.exports = (req, res) => {
  const name = req.body.filename;
  const cmd = `tar czf /tmp/${name}.tgz ./uploads/${name}`;
~>  exec(cmd);
  res.sendStatus(204);
};
