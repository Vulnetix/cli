'use strict';

const crypto = require('crypto');
const fs = require('fs');
const hashIt = require('blueimp-md5');

function fingerprintBundle(bundlePath) {
  return new Promise((resolve, reject) => {
    const h = crypto
~>      .createHash('md5');
    fs.createReadStream(bundlePath)
      .on('data', (chunk) => h.update(chunk))
      .on('end', () => resolve(h.digest('hex')))
      .on('error', reject);
  });
}

function inlineChecksum(source) {
~>  return hashIt(source);
}

module.exports = { fingerprintBundle, inlineChecksum };
