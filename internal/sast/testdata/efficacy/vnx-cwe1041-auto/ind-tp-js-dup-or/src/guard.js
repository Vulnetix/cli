function allowed(user) {
~>  if (user.isAdmin() || user.isAdmin()) {
    return true;
  }
  return false;
}
module.exports = { allowed };
