const express = require('express');
const helmet = require('helmet');

~>const app = express();
app.use(helmet.frameguard());
app.use(helmet.noSniff());
/*
app.use(helmet.contentSecurityPolicy());
*/
// app.use(helmet());
app.use(express.static('public'));
app.listen(3000);
