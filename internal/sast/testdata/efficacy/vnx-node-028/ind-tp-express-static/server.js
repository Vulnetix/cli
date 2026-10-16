const express = require('express');
const path = require('path');
const compression = require('compression');

~>const app = express();
app.use(compression());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.listen(3000);
