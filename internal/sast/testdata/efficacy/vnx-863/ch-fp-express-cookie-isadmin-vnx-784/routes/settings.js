function updateSettings(req, res) {
  // Reported by VNX-784 (a security decision on a cookie), not by this rule.
  if (req.cookies.isAdmin === 'true') {
    saveSettings(req.body);
    return res.sendStatus(204);
  }
  res.sendStatus(403);
}

module.exports = { updateSettings };
