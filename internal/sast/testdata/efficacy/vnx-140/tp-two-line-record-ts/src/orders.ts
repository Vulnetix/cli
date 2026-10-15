import { createWriteStream } from 'fs'
import { Request, Response } from 'express'

const sink = createWriteStream('orders.csv', { flags: 'a' })

export function addOrder (req: Request, res: Response) {
  const { item, qty } = req.body
  const line = [req.body.item, req.body.qty, req.ip].join(',')
~>  sink.write(line + '\n')
  res.sendStatus(201)
}
