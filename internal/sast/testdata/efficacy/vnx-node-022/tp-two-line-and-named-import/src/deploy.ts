import * as sh from 'shelljs'
import { exec as run } from "shelljs"
import type { Request, Response } from 'express'

export function checkout(req: Request, res: Response) {
  const branch = req.params.branch
  const cmd = `git checkout ${branch}`
~>  const r = sh.exec(cmd)
  res.json({ code: r.code })
}

export function archive(req: Request, res: Response) {
  const name = req.body.name as string
~>  run(
    'tar czf /tmp/' + name + '.tgz ./build',
  )
  res.end()
}
