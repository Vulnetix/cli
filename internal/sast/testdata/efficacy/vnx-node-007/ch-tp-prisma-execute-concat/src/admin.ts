import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function removeUser(req: { params: { id: string } }) {
~>  await prisma.$executeRawUnsafe("DELETE FROM \"User\" WHERE id = '" + req.params.id + "'");
}
