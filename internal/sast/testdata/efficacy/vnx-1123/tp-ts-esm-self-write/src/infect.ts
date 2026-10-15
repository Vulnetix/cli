import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

export async function infect(code: string): Promise<void> {
~>  await writeFile(fileURLToPath(import.meta.url), code);
}
