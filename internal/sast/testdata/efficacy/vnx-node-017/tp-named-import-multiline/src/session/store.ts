import { Request, Response } from 'express'
import { unserialize } from "node-serialize"
import * as ns from 'node-serialize'

export function loadDraft(req: Request, res: Response) {
~>  const draft = unserialize(req.query.draft as string)
  res.json(draft)
}

export function loadPrefs(blob: string) {
~>  return ns.unserialize(
    blob,
  )
}
