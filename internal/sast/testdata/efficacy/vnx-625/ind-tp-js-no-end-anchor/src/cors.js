function isAllowedOrigin(origin) {
~>  return /^https:\/\/([a-z]+\.)?example\.com/.test(origin)
}
module.exports = { isAllowedOrigin }
