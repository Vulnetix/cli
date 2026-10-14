import { createRemoteJWKSet, jwtVerify } from 'jose'

const JWKS = createRemoteJWKSet(new URL('https://idp.example.com/.well-known/jwks.json'))

export async function verify (token: string) {
~>  const { payload } = await jwtVerify(token, JWKS, {
    issuer: 'https://idp.example.com/',
  })
  return payload
}
