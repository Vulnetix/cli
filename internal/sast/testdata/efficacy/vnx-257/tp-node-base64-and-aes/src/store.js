const CryptoJS = require("crypto-js");

async function register(req) {
  const { password } = req.body;
~>  const encoded = Buffer.from(password).toString("base64");
~>  const enc = CryptoJS.AES.encrypt(password, process.env.KEY).toString();
~>  const obf = btoa(req.body.password);
~>  let out = cipher.update(newPassword, "utf8", "hex");
  await User.create({ password: enc });
}
