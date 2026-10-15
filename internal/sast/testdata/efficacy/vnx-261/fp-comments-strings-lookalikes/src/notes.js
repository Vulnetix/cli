// never do this: btoa(password)
/* Buffer.from(password).toString('base64') is encoding, not hashing */
const help = "base64_encode($password) is reversible";
function encodeTitle(compassDirection) {
  return btoa(compassDirection);
}
module.exports = { help, encodeTitle };
