// crypto.createHash('sha1') must not be used for signatures
const message = "replace createHash('sha1') with createHash('sha256')"

function sql (id) {
  return `SELECT sha1(${id}) AS digest`
}

module.exports = { message, sql }
