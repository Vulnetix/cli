const config = require('config')
const replace = require('replace')

replace({
  regex: /title/,
  replacement: config.get('application.name'),
  paths: ['dist/index.html'],
  silent: true
})

const button = document.querySelector('#save')
button.disabled = true
