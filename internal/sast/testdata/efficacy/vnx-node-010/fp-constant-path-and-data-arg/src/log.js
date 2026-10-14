const fs = require('fs');
const path = require('path');

function log(req, res) {
  fs.appendFileSync('/var/log/app/feedback.log', req.body.message + '\n');
  fs.writeFile(path.join(__dirname, 'last.json'), JSON.stringify(req.query), () => {});
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
}

function settings(req, res) {
  const raw = fs.readFileSync(path.resolve(__dirname, 'config.json'), 'utf8');
  res.json({ raw, user: req.params.user });
}

module.exports = { log, settings };
