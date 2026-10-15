const express = require('express');
const multer = require('multer');

const limits = { fileSize: 5 * 1024 * 1024, files: 3 };
const upload = multer({ storage: multer.memoryStorage(), limits });
const opts = buildOptions();
const other = multer(opts);

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: false, limit: 2 * 1024 * 1024 }));
app.post('/avatar', upload.single('avatar'), (req, res) => res.sendStatus(204));
