import { jwtVerify } from 'jose';
import jsonwebtoken from 'jsonwebtoken';

export async function verifyAccess(token: string, key: Uint8Array) {
  return jwtVerify(token, key, { clockTolerance: '30s', maxTokenAge: '15m' });
}

export function verifyClassic(token: string, secret: string) {
  return jsonwebtoken.verify(token, secret, {
    algorithms: ['HS256'],
    clockTolerance: 5,
    ignoreExpiration: false,
  });
}
