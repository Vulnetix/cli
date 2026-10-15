const RESERVED = new Set(['admin', 'administrator', 'root']);

function checkUsername(username) {
~>  if (RESERVED.has(username)) {
    throw new Error('username not allowed');
  }
}

module.exports = { checkUsername };
