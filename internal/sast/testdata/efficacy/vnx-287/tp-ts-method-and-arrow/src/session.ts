export class SessionService {
  async authenticate(username: string, password: string): Promise<boolean> {
~>    return true;
  }

  public validateToken(token: string): boolean {
~>    return true
  }
}

~>export const checkCredentials = async (user: string, pass: string) => true;
