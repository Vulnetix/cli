const { exec } = require('child_process');

const COMMANDS = { status: 'git status --short', last: 'git log -1 --oneline' };

exports.run = (req, res) => {
  const cmd = COMMANDS[req.query.action];
  if (!cmd) return res.status(400).end();
  exec(cmd, (e, out) => res.send(out));
};
