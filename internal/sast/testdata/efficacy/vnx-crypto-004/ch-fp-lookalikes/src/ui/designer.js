const designer = new Designer();
const desc = row.description;
const supported = crypto.getCiphers().filter((c) => !c.includes("des"));
const c = crypto.createCipheriv("aes-256-gcm", key, iv);
module.exports = { designer, desc, supported, c };
