const express = require('express');
const cors = require('cors');

const allowed = new Set(['https://app.example.com']);
const corsOptions = {
  origin(origin, cb) {
    cb(null, allowed.has(origin));
  },
  credentials: true,
};

const app = express();
app.use(cors(corsOptions));
app.use('/api', cors({ origin: ['https://admin.example.com'] }));
