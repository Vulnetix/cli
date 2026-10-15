import { DataSource } from "typeorm";

export class UsersRepository {
  constructor(private readonly dataSource: DataSource) {}

  findByEmail(email: string) {
~>    return this.dataSource.query(`SELECT * FROM users WHERE email = '${email}'`);
  }

  async search(term: string) {
~>    return this.dataSource.manager.query(
      "SELECT id, name FROM users WHERE name LIKE '%" + term + "%'",
    );
  }
}
