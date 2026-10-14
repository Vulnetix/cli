import { createDecipher as legacyDecipher } from 'node:crypto'
const { createCipher } = require('crypto')

export function seal(data, key) {
~>  const c = createCipher('aes192', key)
  return Buffer.concat([c.update(data), c.final()])
}

export function open(buf, key) {
~>  const d = legacyDecipher('aes192', key)
  return Buffer.concat([d.update(buf), d.final()])
}

export function quick(data, key) {
~>  return require('crypto').createCipher('aes-128-ctr', key).update(data)
}
