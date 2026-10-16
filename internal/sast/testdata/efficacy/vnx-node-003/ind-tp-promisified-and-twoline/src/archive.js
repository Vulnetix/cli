import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export async function unpack(name) {
~>  await execAsync(`tar -xzf uploads/${name} -C /srv/data`);
}

export function history(branch, done) {
  const cmd = `git log --oneline ${branch}`;
~>  exec(cmd, done);
}
