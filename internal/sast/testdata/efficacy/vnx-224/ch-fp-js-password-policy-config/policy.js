const passwordPolicy = { minLength: 12, requireDigit: true };

function exportPolicy() {
  const blob = btoa(JSON.stringify(passwordPolicy));
  console.info("password policy exported", blob.length);
  return blob;
}

module.exports = { exportPolicy };
