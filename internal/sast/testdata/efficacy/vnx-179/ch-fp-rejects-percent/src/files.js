function serve(req, res) {
  const file = req.params.file;
  if (file.includes('..') || file.includes('%')) {
    return res.status(400).end();
  }
  const name = decodeURIComponent(file);
  return res.sendFile(name, { root: '/srv/static' });
}

module.exports = { serve };
