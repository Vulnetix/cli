import * as crypto from 'crypto'
import sha1 from 'sha1'
import CryptoJS from 'crypto-js'

~>export const passwordHash = (pw: string) => crypto.createHash('sha1').update(pw).digest('hex')

export function integrity (body: Buffer): string {
  return crypto
~>    .createHash("SHA1")
    .update(body)
    .digest('base64')
}

export function sign (key: string, data: string): string {
~>  const signer = crypto.createSign('RSA-SHA1')
  signer.update(data)
  return signer.sign(key, 'base64')
}

export function wrapped (body: string): string {
~>  const h = crypto.createHash(
    `sha1`
  )
  return h.update(body).digest('hex')
}

export function viaPackage (body: string): string {
~>  return sha1(body)
}

export function viaCryptoJs (body: string): string {
~>  return CryptoJS.SHA1(body).toString()
}
