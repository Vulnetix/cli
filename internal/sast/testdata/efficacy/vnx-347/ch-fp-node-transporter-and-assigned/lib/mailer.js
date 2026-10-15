const crypto = require("crypto");
const nodemailer = require("nodemailer");

async function start(config) {
  const transporter = nodemailer.createTransport(config.smtp);
  await transporter.verify();
  return transporter;
}

async function checkToken(key, sig, data) {
  const ok = await crypto.subtle.verify(
    "Ed25519",
    key,
    sig,
    data
  );
  if (!ok) throw new Error("bad signature");
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(data)) && ok;
}

module.exports = { start, checkToken };
