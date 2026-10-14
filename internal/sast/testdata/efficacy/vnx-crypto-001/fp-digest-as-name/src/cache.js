const md5 = require('md5')

function cacheFile (url) {
  return 'cache/' + md5(url) + '.json'
}

module.exports = { cacheFile }
