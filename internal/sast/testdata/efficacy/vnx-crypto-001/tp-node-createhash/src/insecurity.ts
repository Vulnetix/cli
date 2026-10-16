import crypto from 'crypto'
import md5 from 'md5'
const CryptoJS = require('crypto-js')

~>export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

export function passwordDigest (password: string): string {
  return crypto
~>    .createHash("MD5")
    .update(password)
    .digest('hex')
}

export function sessionId (user: string): string {
  return crypto.createHash(`md5`).update(`${user}:${Date.now()}`).digest('base64')
}

export function wrapped (body: string): string {
~>  const h = crypto.createHash(
    'md5'
  )
  return h.update(body).digest('hex')
}

export function viaPackage (body: string): string {
~>  return md5(body)
}

export function viaCryptoJs (body: string): string {
~>  return CryptoJS.MD5(body).toString()
}
