import child_process from 'child_process';

export function log(branch, done) {
  const cmd = `git log --oneline ${branch}`;
~>  child_process.exec(cmd, done);
}
