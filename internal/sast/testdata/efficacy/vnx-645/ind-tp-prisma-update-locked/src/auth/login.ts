import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';

const prisma = new PrismaClient();
const LIMIT = 3;

export async function verifyLogin(username: string, password: string): Promise<boolean> {
  const account = await prisma.account.findUnique({ where: { username } });
  if (!account || account.locked) return false;
  if (await argon2.verify(account.hash, password)) {
    await prisma.account.update({ where: { id: account.id }, data: { failedCount: 0 } });
    return true;
  }
  const failedCount = account.failedCount + 1;
  if (failedCount >= LIMIT) {
~>    await prisma.account.update({ where: { id: account.id }, data: { failedCount, locked: true } });
    return false;
  }
  await prisma.account.update({ where: { id: account.id }, data: { failedCount } });
  return false;
}
