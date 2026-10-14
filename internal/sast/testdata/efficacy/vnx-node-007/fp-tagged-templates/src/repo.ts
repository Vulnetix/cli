import sql from "postgres-tag";
import { Prisma } from "@prisma/client";

export async function byId(db: any, prisma: any, id: string) {
  await db.query(sql`SELECT * FROM users WHERE id = ${id}`);
  await prisma.$queryRaw`SELECT * FROM "User" WHERE id = ${id}`;
  return prisma.$queryRaw(Prisma.sql`SELECT * FROM "User" WHERE id = ${id}`);
}
