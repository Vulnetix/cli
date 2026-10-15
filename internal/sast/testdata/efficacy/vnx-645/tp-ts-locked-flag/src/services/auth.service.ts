export class AuthService {
  async validate(email: string, password: string) {
    const account = await this.repo.findByEmail(email);
    if (!(await verify(account.hash, password))) {
      account.failedAttempts++;
      if (account.failedAttempts >= this.maxAttempts) {
~>        account.isLocked = true;
~>        await this.repo.update(account.id, { locked: true });
      }
      await this.repo.save(account);
      throw new UnauthorizedException();
    }
    return account;
  }
}
