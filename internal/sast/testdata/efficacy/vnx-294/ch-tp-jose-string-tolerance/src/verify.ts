import { jwtVerify, createRemoteJWKSet } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://id.example.com/.well-known/jwks.json'));

export async function verifyAccess(token: string) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: 'https://id.example.com/',
~>    clockTolerance: '2 days',
  });
  return payload;
}

export async function verifyLegacy(token: string, key: Uint8Array) {
~>  return jwtVerify(token, key, { clockTolerance: "30d" });
}
