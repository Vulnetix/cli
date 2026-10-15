// Never call res.cookie("isAdmin", ...) here: roles live in the session.
const HELP = "Set res.cookie('role', value) only with signed: true";

function describe(req, res) {
  logger.warn("rejected document.cookie = 'role=admin' attempt from %s", req.ip);
  req.session.role = req.user.role;
  res.json({ help: HELP });
}

module.exports = { describe };
