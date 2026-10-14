const c = require('crypto');
~>const h = c.createHash('md5').update(x).digest('hex');
const ok = c.createHash('sha256').update(x).digest('hex');
