const shell = require('shelljs');

module.exports = (req, res) => {
~>  const result = shell.exec(`git clone ${req.body.repo} /tmp/work`, { silent: true });
  res.json({ code: result.code });
};
