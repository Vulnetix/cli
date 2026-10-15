import * as argon2 from 'argon2';

export class AuthService {
  async validate(email: string, password: string) {
    const account = await this.accounts.byEmail(email);
~>    if (!account || !argon2.verify(account.hash, password)) {
      throw new UnauthorizedException();
    }
    return account;
  }
}
