import { generateSync } from 'otplib'
import crypto from 'node:crypto'

// A TOTP secret is per user and comes from the database, not a signing key.
export function code(user: { totpSecret: string }) {
  return generateSync({ secret: user.totpSecret })
}

// The algorithm name is a literal; the key is not.
export function mac(key: Buffer, data: string) {
  return crypto.createHmac('sha256', key).update(data).digest('hex')
}

export const labels = {
  secret: 'Secret',
  tokenSecretLabel: 'Token secret',
}

// app.use(session({ secret: 'keyboard cat' }))
const doc = "jwt.sign(payload, 'secret') hard-codes the key"
export default doc
