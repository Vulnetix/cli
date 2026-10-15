const c = require('crypto');
~>const h = c.createHash('md5').update(password).digest('hex');
const ok = c.createHash('sha256').update(password).digest('hex');
