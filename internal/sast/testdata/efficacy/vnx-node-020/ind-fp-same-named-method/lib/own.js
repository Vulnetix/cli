class Vault {
  createCipher(name) { return name; }
}
const v = new Vault();
const c = v.createCipher('x');
module.exports = c;
