import { execSync } from 'node:child_process';

export function publishRelease(version: string, apiKey: string): void {
~>  execSync(`./bin/release-tool upload --version=${version} --api-key=${apiKey}`, { stdio: 'inherit' });
}
