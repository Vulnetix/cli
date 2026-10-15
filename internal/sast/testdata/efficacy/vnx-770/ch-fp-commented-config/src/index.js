const express = require('express');
const app = express();

// app.use(express.json({ limit: Infinity }))  -- removed, see SEC-112
/*
 * const upload = multer();
 */
const help = "set maxHttpBufferSize: 1e9 only for local testing";
app.use(express.json());
