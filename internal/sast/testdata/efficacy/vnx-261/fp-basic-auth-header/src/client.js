function authHeader(user, password) {
  return 'Basic ' + Buffer.from(`${user}:${password}`).toString('base64');
}
module.exports = { authHeader };
