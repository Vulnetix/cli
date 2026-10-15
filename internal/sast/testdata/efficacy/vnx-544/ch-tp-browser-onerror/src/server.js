const express = require('express');
const path = require('path');

~>const app = express();
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('/api/report', (req, res) => {
  res.json(buildReport(req.query.id));
});
app.listen(8080);
