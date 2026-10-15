const { spawn } = require('child_process');

exports.convert = (req, res) => {
~>  const p = spawn(`convert uploads/${req.query.file} out.png`, {
    shell: true,
  });
  p.on('exit', (c) => res.json({ c }));
};
