const express = require('express');
const app = express();

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
app.listen(8080);
