import { Request, Response } from 'express'
import * as fs from 'fs'
import path from 'path'

const REPORT_DIR = path.join(__dirname, '../../reports')

export const downloadReport = () => ({ params, query }: Request, res: Response) => {
  const name = params.name
  const format = query.format || 'pdf'
~>  const stream = fs.createReadStream(path.join(REPORT_DIR, `${name}.${format}`))
  stream.pipe(res)
}

export const previewReport = async ({ query }: Request, res: Response) => {
~>  const text = await fs.promises.readFile(path.join(REPORT_DIR, query.file as string), 'utf8')
  res.type('text/plain').send(text)
}
