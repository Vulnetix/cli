import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

export async function computeIntegrity(file) {
  const data = await readFile(file);
~>  const digest = createHash("sha1")
    .update(data)
    .digest('base64');
  return `sha1-${digest}`;
}
