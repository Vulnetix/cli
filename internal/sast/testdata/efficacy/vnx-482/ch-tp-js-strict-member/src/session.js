function login(user, session) {
  if (!user) {
    return false;
  }
~>  session.authenticated === true;
  return session;
}

module.exports = { login };
