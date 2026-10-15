const fs = require('fs')

function scaffold (name) {
  const source = `
import { html } from './index'

export default function ${name} () {
  return html\`<div>${name}</div>\`
}
`
  fs.writeFileSync(`src/${name}.js`, source)
}

module.exports = { scaffold }
