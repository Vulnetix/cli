const express = require('express');
const app = express();
app.use(express.json({ limit: '1gb' }));
const upload = require('multer')({ dest: '/tmp' });
