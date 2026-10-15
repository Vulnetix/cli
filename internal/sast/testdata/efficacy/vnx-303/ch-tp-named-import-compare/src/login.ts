import { compare } from 'bcryptjs';
import { verify as verifyHash } from 'argon2';
import { findUser } from './users';

export async function login(email: string, password: string) {
  const user = await findUser(email);
~>  if (!user || !compare(password, user.passwordHash)) {
    throw new Error('invalid credentials');
  }
  return user;
}

export async function unlock(vault: { hash: string }, secret: string) {
~>  return verifyHash(vault.hash, secret) ? 'open' : 'locked';
}
