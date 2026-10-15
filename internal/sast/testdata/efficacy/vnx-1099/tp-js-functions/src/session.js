export function checkSession(req) {
  return Boolean(req.session && req.session.user && !req.session.expired);
}

~>function check_session(req) {
  return Boolean(req.session);
}

module.exports = { checkSession, check_session };
