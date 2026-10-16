/* build helper */
const pattern = "src/*.js";
const re = /a\/*b/;
const dir = "lib/*/index.js"; // matches /* in the middle of a line
module.exports = { pattern, re, dir };
