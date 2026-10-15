import { execa } from 'execa';

export async function login(registry: string, user: string, token: string) {
~>  await execa('docker', ['login', registry, '-u', user, '--password', token]);
}

export async function publish(npmToken: string) {
~>  await execa('npm', ['publish', `--//registry.npmjs.org/:_authToken=${npmToken}`]);
}
