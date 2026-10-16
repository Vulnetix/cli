const app = require('express')();
// app.post('/login', handler);
/* router.post('/signin', handler) */
const doc = "app.post('/login', handler)";
app.get('/health', (req, res) => res.send('ok'));
