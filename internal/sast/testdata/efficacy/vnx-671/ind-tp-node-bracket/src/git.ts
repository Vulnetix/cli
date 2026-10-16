import { execSync } from 'child_process';

export function pull() {
~>  process.env['GIT_SSL_NO_VERIFY'] = 'true';
  execSync('git pull');
}
