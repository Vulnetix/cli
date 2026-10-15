const app = require('express')();

// app.post('/login', legacyLogin);
app.post('/api/orders', createOrder);
const help = "POST to app.post('/login') is handled by the SSO proxy";
