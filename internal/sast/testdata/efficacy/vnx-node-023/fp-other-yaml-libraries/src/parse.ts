import YAML from 'yaml'
import type { Request } from 'express'

// eemeli/yaml has no JavaScript types: parse() of caller input is safe.
export function parse(req: Request) {
  return YAML.parse(req.body)
}

export function parseDocument(req: Request) {
  const doc = YAML.parseDocument(req.body)
  return doc.toJS()
}

// Bad, for comparison: yaml.load(req.body) with js-yaml 3.
const note = 'js-yaml load(req.body) evaluates !!js/function'
export default note
