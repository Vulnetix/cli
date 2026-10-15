import { readFile } from 'fs/promises';
import * as path from 'path';

export async function show(request: any, reply: any) {
  const target = path.resolve('./data', request.params.doc);
~>  const text = await readFile(target, 'utf8');
  return reply.send(text);
}
