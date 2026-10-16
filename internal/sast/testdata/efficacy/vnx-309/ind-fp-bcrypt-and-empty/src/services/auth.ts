import bcrypt from 'bcrypt';

export async function verify(user: { passwordHash: string }, password: string) {
  if (password === '') {
    return false;
  }
  return bcrypt.compare(password, user.passwordHash);
}
