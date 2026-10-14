import * as nodeCrypto from 'crypto'

export function encryptLegacy(plain: string, secret: string): string {
~>  const cipher = nodeCrypto.createCipher(
    'aes-256-ctr',
    secret,
  )
  return cipher.update(plain, 'utf8', 'base64') + cipher.final('base64')
}
