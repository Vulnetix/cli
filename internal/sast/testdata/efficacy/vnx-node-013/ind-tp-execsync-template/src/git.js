const { execSync } = require('child_process');

app.post('/log', (req, res) => {
~>  const out = execSync(`git log --oneline ${req.body.ref}`, { cwd: REPO });
  res.send(out.toString());
});
