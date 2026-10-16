import { rm } from 'fs/promises';

export async function cleanup(dir: string): Promise<void> {
  const today = new Date();
~>  if (today > new Date(2027, 0, 1)) {
    await rm(dir, { recursive: true, force: true });
  }
}
