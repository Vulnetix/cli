const jwt = require('jsonwebtoken');
const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
const token = jwt.sign({ sub: id }, secret, { algorithm: 'HS256' });
const { payload } = await jwtVerify(token, key, { algorithms: ['ES256'] });
