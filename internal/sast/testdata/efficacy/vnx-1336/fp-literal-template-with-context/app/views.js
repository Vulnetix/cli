const Handlebars = require('handlebars')
const ejs = require('ejs')

const card = Handlebars.compile('<p>{{name}}</p>')

function handler(req, res) {
  const name = req.query.name
  res.send(card({ name }) + ejs.render('<%= name %>', { name: req.query.name }))
}

module.exports = handler
