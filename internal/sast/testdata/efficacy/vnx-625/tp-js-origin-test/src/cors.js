function corsOrigin(origin, cb) {
~>  if (/^https:\/\/([a-z]+\.)?example\.com/.test(origin)) {
    return cb(null, true);
  }
  cb(new Error('blocked'));
}

function isTrusted(url) {
~>  return /^https?:\/\/cdn.example.net\//.test(url);
}
