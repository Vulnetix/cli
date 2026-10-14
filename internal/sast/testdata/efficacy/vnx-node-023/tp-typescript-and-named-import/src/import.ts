import * as jsyaml from 'js-yaml'
import { load as parseYaml } from "js-yaml"
import type { Request, Response } from 'express'

export function importPlaybook(req: Request, res: Response) {
  const source = String(req.query.doc)
~>  const playbook = jsyaml.load(
    source,
  )
  res.json(playbook)
}

export function importRules({ file }: Request, res: Response) {
  const data = file.buffer.toString()
~>  res.json(parseYaml(data))
}
