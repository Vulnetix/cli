import * as childProc from 'node:child_process';

export function log(ref: string) {
~>  return childProc.spawnSync('git', ['log', ref], { shell: true }).stdout.toString();
}
