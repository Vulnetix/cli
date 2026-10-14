import Redis from "ioredis";
import { evaluate } from "mathjs";

const redis = new Redis();

export async function bump(key: string, script: string) {
  await redis.eval(script, 1, key);
  const total = evaluate(key);
  await page.evaluate(() => document.title);
  return this.eval(total);
}
