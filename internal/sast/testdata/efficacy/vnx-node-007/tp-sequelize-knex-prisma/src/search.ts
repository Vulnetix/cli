import { sequelize } from "./models";
import { knex } from "./db";
import { prisma } from "./prisma";

export async function search(criteria: string, col: string, id: string) {
~>  await sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%' ORDER BY name`);
~>  await knex("users").whereRaw("name = '" + criteria + "'");
~>  await knex.raw(`SELECT ${col} FROM users`);
~>  return prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE id = ${id}`);
}
