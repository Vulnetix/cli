// crypto.createCipheriv('des-cbc', key, iv) was the old scheme
const help = "Never call crypto.createCipheriv('rc4', key, null)"
const description = 'Triple DES (3DES) is deprecated; RC4 is broken'

function describe (desc, rc4Count) {
  return `${desc}: ${rc4Count}`
}

module.exports = { help, description, describe }
