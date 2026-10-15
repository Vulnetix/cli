function checkUsername(username) {
~>  if (!/[a-z0-9_]+$/.test(username)) {
    throw new Error("invalid username");
  }
  return username;
}
module.exports = { checkUsername };
