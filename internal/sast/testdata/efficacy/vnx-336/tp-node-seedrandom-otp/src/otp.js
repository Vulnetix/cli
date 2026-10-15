const seedrandom = require('seedrandom');

~>const rng = seedrandom('otp-service');

function generateOtp() {
  return String(Math.floor(rng() * 1e6)).padStart(6, '0');
}

module.exports = { generateOtp };
