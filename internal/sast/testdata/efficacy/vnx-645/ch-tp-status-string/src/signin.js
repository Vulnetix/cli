async function signIn(username, password) {
  const user = await repo.findByName(username);
  if (!(await verifyPassword(user, password))) {
    user.failedAttempts += 1;
    if (user.failedAttempts >= MAX_FAILED) {
~>      user.status = "LOCKED";
    }
    await repo.save(user);
    return null;
  }
  return user;
}
