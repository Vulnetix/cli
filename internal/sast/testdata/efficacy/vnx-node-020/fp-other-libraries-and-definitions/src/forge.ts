import forge from 'node-forge'

// node-forge takes the IV in start({ iv }), so its createCipher is not Node's.
export function forgeEncrypt(key: string, iv: string, data: string) {
  const cipher = forge.cipher.createCipher('AES-CBC', key)
  cipher.start({ iv })
  cipher.update(forge.util.createBuffer(data))
  cipher.finish()
  return cipher.output.toHex()
}

export class CipherFactory {
  createCipher(algorithm: string) {
    return { algorithm }
  }
}

function createDecipher(name: string) {
  return name
}

export const f = new CipherFactory()
export const made = f.createCipher('noop')
export const d = createDecipher('noop')
