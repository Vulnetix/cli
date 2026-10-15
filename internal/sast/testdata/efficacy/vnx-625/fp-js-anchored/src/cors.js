function corsOrigin(origin) {
  return /^https:\/\/([a-z]+\.)?example\.com$/.test(origin);
}
const cdn = /^https?:\/\/cdn\.example\.net\//;
const re = new RegExp('^https://(www\\.)?example\\.com(/|$)');
