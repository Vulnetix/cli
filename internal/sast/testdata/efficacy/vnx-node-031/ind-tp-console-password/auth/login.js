async function login(username, password) {
~>  console.log('login attempt', username, password);
  return verify(username, password);
}
module.exports = login;
