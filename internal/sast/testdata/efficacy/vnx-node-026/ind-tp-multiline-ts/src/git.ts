import { spawnSync } from 'node:child_process';

export function checkout(repoDir: string, branch: string) {
~>  const r = spawnSync(`git checkout ${branch}`, {
    cwd: repoDir,
    encoding: 'utf8',
    shell: true,
  });
  return r.status === 0;
}
