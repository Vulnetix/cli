export function newUser(email: string) {
  const user = { email, mfaEnabled: false, createdAt: new Date() };
  return user;
}

export function disableForUser(user: { mfaEnabled: boolean }) {
  user.mfaEnabled = false;
}
