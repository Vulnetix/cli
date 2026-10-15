import * as argon2 from "argon2";

const DUMMY = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

export async function validate(users: any, email: string, password: string) {
  const user = await users.findByEmail(email);
  if (!user) {
    await argon2.verify(DUMMY, password);
    return null;
  }
  return (await argon2.verify(user.passwordHash, password)) ? user : null;
}
