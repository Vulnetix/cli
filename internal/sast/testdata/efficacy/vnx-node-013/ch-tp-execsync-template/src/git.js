const { execSync } = require('child_process');

exports.log = (req, res) => {
~>  const out = execSync(`git log --oneline --author=${req.query.author}`);
  res.type('text').send(out);
};
