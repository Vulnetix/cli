const express = require('express');
const app = express();

app.use((req, res, next) => {
~>  if (req.path.startsWith('/admin') && !req.session.isAdmin) {
    return res.status(403).send('Forbidden');
  }
~>  if (req.originalUrl === "/api/private/export") {
    return res.sendStatus(401);
  }
  next();
});
