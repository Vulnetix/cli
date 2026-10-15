const bodyParser = require('body-parser');
const app = require('express')();

~>app.use(bodyParser.urlencoded({ extended: true, limit: 1024 * 1024 * 1024 }));
app.use(bodyParser.json({ limit: 100 * 1024 }));
