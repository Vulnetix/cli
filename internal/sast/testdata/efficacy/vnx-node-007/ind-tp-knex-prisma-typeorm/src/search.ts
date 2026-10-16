import knex from 'knex';
import { PrismaClient } from '@prisma/client';

const db = knex({ client: 'pg' });
const prisma = new PrismaClient();

export function byName(criteria: string) {
~>  return db('users').whereRaw("name = '" + criteria + "'");
}

export function byId(id: string) {
~>  return prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE id = ${id}`);
}

export function byEmail(repo: any, email: string) {
~>  return repo.createQueryBuilder("user").where(`user.email = '${email}'`).getOne();
}
