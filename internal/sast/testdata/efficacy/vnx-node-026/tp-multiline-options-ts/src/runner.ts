import * as cp from 'child_process';

export function runTask(command: string, cwd: string): Promise<number> {
  return new Promise((resolve) => {
~>    const proc = cp.spawn(command, {
      cwd,
      stdio: 'inherit',
      shell: true,
    });
    proc.on('exit', (code) => resolve(code ?? 1));
  });
}
