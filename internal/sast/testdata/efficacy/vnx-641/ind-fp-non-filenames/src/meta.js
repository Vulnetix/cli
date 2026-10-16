function majorVersion(version) {
  return version.split('.')[0];
}

function minorVersion(version) {
  return version.split('.')[1];
}

function domainOf(email) {
  const host = email.split('@')[1];
  return host.substring(host.indexOf('.') + 1);
}

function jwtPayload(token) {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
}

function isCdn(hostname) {
  return hostname.includes('.cloudfront.net');
}

// file.originalname.includes('.jpg') is a substring check; use path.extname instead
const HELP = "if (file.originalname.includes('.jpg'))";

module.exports = { majorVersion, minorVersion, domainOf, jwtPayload, isCdn, HELP };
