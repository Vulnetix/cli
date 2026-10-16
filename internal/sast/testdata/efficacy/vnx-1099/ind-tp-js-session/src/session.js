export function checkSession(req) {
  return Boolean(req.session && req.session.user);
}

export function loadUser(id) {
  return db.find(id);
}

~>function check_session(req) {
  return !!req.cookies.sid;
}
