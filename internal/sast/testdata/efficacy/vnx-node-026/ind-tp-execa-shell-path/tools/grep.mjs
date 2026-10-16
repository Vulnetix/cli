import { execa } from 'execa';
import { execFileSync } from 'child_process';

export async function search(pattern, dir) {
~>  return execFileSync('grep', ['-rn', pattern, dir], { shell: '/bin/bash', encoding: 'utf8' });
}

export async function tag(name) {
~>  await execa(`git tag ${name}`, { shell: true });
}
