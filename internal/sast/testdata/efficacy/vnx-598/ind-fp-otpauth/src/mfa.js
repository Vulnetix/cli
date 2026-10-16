const QRCode = require('qrcode');

async function provisioningQr(email, secret) {
  const uri = `otpauth://totp/Acme:${encodeURIComponent(email)}?secret=${secret}&issuer=Acme`;
  return QRCode.toDataURL(uri);
}

module.exports = { provisioningQr };
