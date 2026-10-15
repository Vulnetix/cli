const fs = require('fs');
const pug = require('pug');
const Handlebars = require('handlebars');

const invoice = pug.compileFile('templates/invoice.pug');
const receipt = Handlebars.compile(fs.readFileSync('templates/receipt.hbs', 'utf8'));

exports.render = (req, res) => {
  res.send(invoice({ id: req.params.id }) + receipt({ total: req.body.total }));
};
