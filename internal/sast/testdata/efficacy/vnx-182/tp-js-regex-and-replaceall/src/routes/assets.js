const path = require('path');
const fs = require('fs');

function readAsset(req, res) {
~>  const name = req.params.name.replace(/\.\.\//g, '');
  fs.createReadStream(path.join(__dirname, 'assets', name)).pipe(res);
}

function readTheme(req, res) {
  let theme = req.query.theme;
~>  theme = theme.replaceAll("../", "");
  res.sendFile(path.join(__dirname, 'themes', theme));
}

function greet(req, res) {
~>  const who = String(req.query.who).replace(/<script>/gi, ``);
  res.send(`<p>Hello ${who}</p>`);
}

module.exports = { readAsset, readTheme, greet };
