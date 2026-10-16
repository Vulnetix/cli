function uri(label, secretB32) {
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=Acme`;
}

async function get(token) {
  return fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } });
}
