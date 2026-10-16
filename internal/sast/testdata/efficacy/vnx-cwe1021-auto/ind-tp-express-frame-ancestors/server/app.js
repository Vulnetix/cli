const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use((req, res, next) => {
~>  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors *");
  next();
});

app.listen(3000);
