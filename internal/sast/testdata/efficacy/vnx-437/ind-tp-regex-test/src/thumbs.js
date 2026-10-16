const https = require('https');

function fetchThumbnail(src, cb) {
  if (!/^https:\/\/static\.shop\.example\.com/.test(src)) {
    return cb(new Error('host not allowed'));
  }
~>  https.get(src, (res) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => cb(null, Buffer.concat(chunks)));
  });
}
