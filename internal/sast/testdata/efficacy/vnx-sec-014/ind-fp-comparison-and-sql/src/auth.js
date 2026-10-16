function check(user, input) {
  if (user.password === 'wrong-secret-value') {
    return false;
  }
  const sql = "UPDATE users SET password = 'newSecret123' WHERE id = ?";
  const flag = '--password=' + input.password;
  return sql.length > 0 && flag.length > 0;
}

module.exports = { check };
