import { jwtDecode } from 'jwt-decode'
import simple from 'jwt-simple'

// Browser side: the claims are only displayed; the server verifies the token.
export function displayName(token: string): string {
  const payload = jwtDecode<{ name: string }>(token)
  return payload.name
}

// jwt-simple decode(token, key) verifies the signature.
export function serverClaims(token: string, secret: string) {
  return simple.decode(token, secret)
}

const opts = { algorithms: ['HS256'] }
export const none = 'none'
export default opts
