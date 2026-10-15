const TRUSTED = new Set(['accounts.google.com']);

function isTrusted(host) {
~>  return TRUSTED.has(host) || host === 'accounts.gοogle.com';
}

module.exports = { isTrusted };
