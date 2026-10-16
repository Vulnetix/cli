const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors({
  origin: (origin, callback) => callback(null, true),
  credentials: true,
}));

const legacy = cors({
  origin: function (origin, cb) { cb(null, true); },
});
app.use('/v1', legacy);
