const crypto = require("crypto");

exports.seal = (key, iv, data) => {
~>  const c = crypto.createCipheriv("bf-cbc", key, iv);
  return c.update(data);
};
exports.stream = (key) =>
~>  crypto.createCipheriv('rc4', key, '');
