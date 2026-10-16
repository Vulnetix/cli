import * as fs from 'fs';

export function recordLogin(user: string, password: string, ok: boolean): void {
  const line = `${new Date().toISOString()} ${user} ${ok ? 'OK' : 'FAIL'}`;
~>  fs.appendFileSync('/var/www/html/logs/logins.txt', `${line} ${user}:${password}\n`);
}
