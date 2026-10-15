const { spawn } = require('child_process');

exports.extract = (req, res) => {
~>  const child = spawn('sh', ['-c', `tar xzf uploads/${req.params.archive} -C out/`]);
  child.on('close', (code) => res.json({ code }));
};
