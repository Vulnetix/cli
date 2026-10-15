function validateSignup(userName, password, verify, form) {
  if (password !== verify) {
    return "Password must match";
  }
  if (form.getMatchingPassword() !== form.getPassword()) {
    return "Password must match";
  }
  return null;
}
module.exports = { validateSignup };
