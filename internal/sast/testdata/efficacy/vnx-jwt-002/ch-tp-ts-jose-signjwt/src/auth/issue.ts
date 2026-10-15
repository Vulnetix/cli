import { SignJWT } from 'jose';

export async function issue(userId: string, key: Uint8Array): Promise<string> {
~>  return await new SignJWT({ sub: userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .sign(key);
}
