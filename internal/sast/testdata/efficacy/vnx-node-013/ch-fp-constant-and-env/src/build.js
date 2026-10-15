const { exec } = require('child_process');

exports.build = (req, res) => {
  exec('npm run build --silent', (err) => res.json({ ok: !err, user: req.user.id }));
  exec(`docker restart ${process.env.CONTAINER_NAME}`);
};
