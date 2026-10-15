const path = require('path');
const ROOT = path.join(__dirname, 'public');

module.exports = function serveStatic(req, res, next) {
~>  if (req.path.startsWith('/private/') && !req.session.admin) {
    return res.sendStatus(403);
  }
  const file = path.join(ROOT, decodeURIComponent(req.path));
  res.sendFile(file);
};
