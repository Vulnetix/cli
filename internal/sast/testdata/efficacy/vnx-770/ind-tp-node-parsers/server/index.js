const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const app = express();

~>app.use(express.json({ limit: '2gb' }));
~>app.use(bodyParser.urlencoded({ extended: true, limit: '100mb' }));
~>app.use(express.raw({ limit: Infinity }));
~>const upload = multer({ dest: '/tmp/uploads' });
