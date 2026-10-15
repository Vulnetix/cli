const path = require('path');

app.get('/assets/*', (req, res) => {
~>  const rel = req.params[0].replace(/^[.\/\\]+/, '');
  res.sendFile(path.join(ASSET_DIR, rel));
});

function stripCmd(arg) {
~>  return arg.replace(/[;&|`]+$/, '');
}
