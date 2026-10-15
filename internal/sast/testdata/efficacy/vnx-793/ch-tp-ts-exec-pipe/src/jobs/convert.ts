import { exec } from 'child_process';

export function convert(input: string): void {
~>  const arg = input.replace('|', '').replace('&&', '');
  exec(`convert ${arg} out.png`);
}
