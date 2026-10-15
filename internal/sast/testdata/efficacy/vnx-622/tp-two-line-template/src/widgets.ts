import { Request, Response } from 'express'

export function widget (req: Request, res: Response) {
  const cb = req.query.cb as string
  const payload = JSON.stringify(loadWidget(req.params.id))
  res.setHeader('Content-Type', 'application/javascript')
~>  res.send(`${cb}(${payload})`)
}

export function legacy (req: Request, res: Response) {
  const fn = req.body.callback
~>  res.write(fn + '(' + JSON.stringify({ ok: true }) + ')')
  res.end()
}
