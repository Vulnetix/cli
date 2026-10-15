function updateSettings(req, res) {
~>  if (req.cookies.isAdmin === 'true') {
    saveSettings(req.body);
    return res.sendStatus(204);
  }
  res.sendStatus(403);
}

module.exports = { updateSettings };
