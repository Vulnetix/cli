import crypto from 'crypto'
import CryptoJS from 'crypto-js'

const LEGACY_ALGO = 'des-ede3-cbc'

export function seal (key: Buffer, iv: Buffer, data: string): string {
~>  const c = crypto.createCipheriv('des-cbc', key, iv)
  return c.update(data, 'utf8', 'hex') + c.final('hex')
}

export function sealTriple (key: Buffer, iv: Buffer, data: string): string {
~>  const c = crypto.createCipheriv(LEGACY_ALGO, key, iv)
  return c.update(data, 'utf8', 'hex') + c.final('hex')
}

export function rc4 (key: Buffer, data: Buffer): Buffer {
~>  const c = crypto.createCipheriv("rc4", key, null)
  return Buffer.concat([c.update(data), c.final()])
}

export function blowfish (key: Buffer, iv: Buffer, data: Buffer): Buffer {
~>  const d = crypto.createDecipheriv('bf-cbc', key, iv)
  return Buffer.concat([d.update(data), d.final()])
}

export function browser (msg: string, key: string): string {
~>  return CryptoJS.TripleDES.encrypt(msg, key).toString()
}

export function browserDes (msg: string, key: string): string {
~>  return CryptoJS.DES.encrypt(msg, key).toString()
}
