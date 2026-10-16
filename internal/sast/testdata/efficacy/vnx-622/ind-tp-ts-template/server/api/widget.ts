import { Request, Response } from 'express'

export function widget(req: Request, res: Response) {
  const payload = JSON.stringify({ count: 3 })
  const jsonp = req.query.jsonp as string
  res.set('Content-Type', 'text/javascript')
~>  res.send(`${jsonp}(${payload})`)
}
