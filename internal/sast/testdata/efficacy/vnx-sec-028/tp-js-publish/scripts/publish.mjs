import { execSync } from "node:child_process";

~>const token = 'npm_@@sample:[A-Za-z0-9]{36}@@';
execSync(`npm publish --//registry.npmjs.org/:_authToken=${token}`);
