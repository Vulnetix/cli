import { createWriteStream } from 'fs'
import { Request, Response } from 'express'

const sink = createWriteStream('feedback.tsv', { flags: 'a' })

export function saveFeedback(req: Request, res: Response) {
  const rating = req.body.rating
  const comment = req.body.comment
  const row = [req.query.page, rating, comment].join('\t')
~>  sink.write(row + '\n')
  res.status(201).end()
}
