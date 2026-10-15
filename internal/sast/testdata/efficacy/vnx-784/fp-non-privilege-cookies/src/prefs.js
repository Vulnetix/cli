function prefs(req, res) {
  if (req.cookies.theme === "dark") {
    res.locals.dark = true;
  }
  const lang = req.cookies["lang"];
  if (lang === "fr") {
    res.locals.locale = "fr";
  }
  const sid = req.cookies.session_id;
  return lookupSession(sid);
}
module.exports = prefs;
