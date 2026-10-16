const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const app = express();

app.use(express.json({ limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '1mb', parameterLimit: 1000 }));
const upload = multer({
  dest: '/tmp/uploads',
  limits: { fileSize: 5 * 1024 * 1024, files: 2 },
});
const io = new Server(httpServer, { maxHttpBufferSize: 1e6 });
app.use(express.json());
