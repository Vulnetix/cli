// Sample token copied from the jwt.io debugger, used in the decode demo.
const sample = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

function decodeDemo() {
  const [, payload] = sample.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString());
}

module.exports = { decodeDemo };
