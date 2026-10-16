const crypto = require('crypto');

function encrypt(text, iv) {
~>  const cipher = crypto.createCipheriv('aes-256-cbc', '@@sample:a[3]f9[c]2e[1]7b[8]d4[0]65[a]3f[9]c2[e]17[b]8d[4]06[5]@@', iv);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function sign(body) {
  return crypto.createHmac('sha256', 'webhook-signing-secret').update(body).digest('hex');
}

~>const enc = CryptoJS.AES.encrypt(data, "@@sample:M[y]Su[p]er[S]ec[r]et[P]as[s]12[3]@@");
