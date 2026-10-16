const { execFile } = require('child_process');

function flushCache(host, redisPassword) {
  return new Promise((resolve, reject) => {
~>    execFile('redis-cli', ['-h', host, '-a', redisPassword, 'FLUSHDB'], (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout.trim());
    });
  });
}

module.exports = { flushCache };
