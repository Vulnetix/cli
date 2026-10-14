const express = require('express');
const csrf = require('csurf');

const app = express();
app.use(express.json());
~>// const csrfProtection = csrf({ cookie: true });
// app.use(csrfProtection);
// app.use((req, res, next) => {
//   res.locals.csrfToken = req.csrfToken();
//   next();
// });
app.use('/api', require('./routes'));

module.exports = app;
