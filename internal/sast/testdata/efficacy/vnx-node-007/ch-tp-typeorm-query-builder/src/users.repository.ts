import { DataSource } from "typeorm";
import { User } from "./user.entity";

export class UsersRepository {
  constructor(private readonly ds: DataSource) {}

  findByEmail(email: string) {
    return this.ds
      .getRepository(User)
      .createQueryBuilder("user")
~>      .where(`user.email = '${email}'`)
      .getOne();
  }

  findByName(name: string) {
    return this.ds
      .getRepository(User)
      .createQueryBuilder("user")
      .where("user.name = :name", { name })
      .andWhere("user.active = true")
      .getMany();
  }
}
