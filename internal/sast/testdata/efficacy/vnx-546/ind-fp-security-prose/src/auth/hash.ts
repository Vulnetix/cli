import bcrypt from 'bcrypt';

// Passwords are hashed with bcrypt before storage and are never logged.
// Input is validated by the zod schema in ./schema.ts before it reaches here.
export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, 12);
}
