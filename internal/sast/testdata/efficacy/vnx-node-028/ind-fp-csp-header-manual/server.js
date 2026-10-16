const express = require('express');
const app = express();

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
  next();
});
app.use(express.static('public'));
app.get('/', (req, res) => res.render('index'));
app.listen(3000);
