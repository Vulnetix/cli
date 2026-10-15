import { spawn, SpawnOptions } from 'child_process';

export function exec(command: string): void {
  const opts: SpawnOptions = {
    cwd: process.cwd(),
    shell: true,
  };
~>  spawn(command, opts);
}
