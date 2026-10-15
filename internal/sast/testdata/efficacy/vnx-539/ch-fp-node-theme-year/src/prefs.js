const ONE_YEAR = 365 * 24 * 60 * 60 * 1000;

function savePrefs(req, res) {
  res.cookie('theme', req.body.theme, { maxAge: 365 * 24 * 60 * 60 * 1000 });
  res.cookie('locale', req.body.locale, { maxAge: ONE_YEAR });
  res.cookie('sid', req.sessionID, { httpOnly: true });
  res.sendStatus(204);
}

module.exports = { savePrefs };
