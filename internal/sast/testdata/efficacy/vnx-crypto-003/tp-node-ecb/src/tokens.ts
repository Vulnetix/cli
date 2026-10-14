import crypto from 'crypto'
import CryptoJS from 'crypto-js'
import aesjs from 'aes-js'

const ALGORITHM = 'aes-192-ecb'

export function seal (key: Buffer, data: string): string {
~>  const cipher = crypto.createCipheriv('aes-128-ecb', key, null)
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex')
}

export function open (key: Buffer, data: string): string {
~>  const decipher = crypto.createDecipheriv("AES-256-ECB", key, Buffer.alloc(0))
  return decipher.update(data, 'hex', 'utf8') + decipher.final('utf8')
}

export function configured (key: Buffer, data: string): string {
~>  const cipher = crypto.createCipheriv(ALGORITHM, key, null)
  return cipher.update(data, 'utf8', 'base64') + cipher.final('base64')
}

export function browser (msg: string, key: string): string {
  return CryptoJS.AES.encrypt(msg, CryptoJS.enc.Utf8.parse(key), {
~>    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  }).toString()
}

export function viaAesJs (key: Uint8Array, block: Uint8Array): Uint8Array {
~>  const ecb = new aesjs.ModeOfOperation.ecb(key)
  return ecb.encrypt(block)
}
