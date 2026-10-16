const ejs = require('ejs');
const fs = require('fs');
const fileTemplate = fs.readFileSync(__dirname + '/mail.ejs', 'utf8');

app.post('/mail', (req, res) => {
  res.send(ejs.render(fileTemplate, { user: req.body }));
});
