import fs from 'node:fs';

export async function dumpDebug() {
~>  await fs.promises.writeFile('./public/debug.json', JSON.stringify(process.env, null, 2));
}
