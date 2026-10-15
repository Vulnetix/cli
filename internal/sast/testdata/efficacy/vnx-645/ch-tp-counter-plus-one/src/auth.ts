export async function authenticate(name: string, password: string) {
  const account = await accounts.byName(name);
  if (!(await compare(password, account.hash))) {
    if (account.failedAttempts + 1 >= 3) {
~>      account.isLocked = true;
    }
    account.failedAttempts++;
    await accounts.save(account);
    return false;
  }
  return true;
}
