const fs = require('fs');
const yaml = require('js-yaml');

function explain(req, res) {
  const key = req.body.key;
  if (!/^[a-zA-Z]+$/.test(key)) {
    return res.status(400).end();
  }
  const info = yaml.load(fs.readFileSync('./data/fixes/' + key + '.info.yml', 'utf8'));
  res.json(info);
}

module.exports = { explain };
