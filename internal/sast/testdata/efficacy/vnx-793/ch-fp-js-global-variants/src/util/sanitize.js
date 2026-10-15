const sanitize = (p) => p.replace(/\.\.\//g, '').replace(/[;&|`$]/g, '');
const crlf = (h) => h.replace(/\r\n/gm, ' ');
const all = (p) => p.replaceAll('../', '');
// p.replace('../', '') would only remove the first one
const msg = "call p.replace('../', '') repeatedly";
module.exports = { sanitize, crlf, all, msg };
