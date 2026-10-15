import { Injectable, UnauthorizedException } from "@nestjs/common";
import * as argon2 from "argon2";
import { UsersService } from "../users/users.service";

@Injectable()
export class AuthService {
  constructor(private readonly users: UsersService) {}

  async validate(email: string, password: string) {
    const user = await this.users.findByEmail(email);
~>    if (user === null) {
      throw new UnauthorizedException();
    }
    const valid = await argon2.verify(user.passwordHash, password);
    if (!valid) throw new UnauthorizedException();
    return user;
  }
}
