function login(req, res, user) {
  res.cookie("role", user.role, { httpOnly: true, signed: true });
  res.cookie("isAdmin", String(user.isAdmin));
  res.clearCookie("admin");
}
module.exports = login;
