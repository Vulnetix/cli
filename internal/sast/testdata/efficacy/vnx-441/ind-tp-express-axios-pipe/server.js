const express = require('express');
const axios = require('axios');

const app = express();

app.get('/media/proxy', async (req, res, next) => {
  try {
    const target = req.query.src;
~>    const upstream = await axios.get(target, { responseType: 'stream', timeout: 8000 });
    res.set('Content-Type', upstream.headers['content-type']);
    upstream.data.pipe(res);
  } catch (err) {
    next(err);
  }
});

module.exports = app;
