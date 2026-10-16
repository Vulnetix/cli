const { spawn } = require('child_process');

app.post('/extract', (req, res) => {
~>  const p = spawn(`tar -xf ${req.body.archive}`, { shell: true });
  p.on('close', (c) => res.json({ code: c }));
});
