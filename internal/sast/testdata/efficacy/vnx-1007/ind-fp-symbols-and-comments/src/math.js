// the user name аdmin (cyrillic a) must be rejected by the validator
const DELTA = 'Δ';
const MICRO = 'μs';
const OHM = 'Ω';
const PI = 3.14159; // π
/* pаypal.com is a known phishing host */
function area(r) { return PI * r * r; }
module.exports = { DELTA, MICRO, OHM, area };
