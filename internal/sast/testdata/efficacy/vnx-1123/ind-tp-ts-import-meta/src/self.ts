import { appendFileSync } from 'node:fs';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';

export function implant(payload: string) {
~>  fs.appendFileSync(fileURLToPath(import.meta.url), payload);
}
