import { Request, Response } from 'express'
import * as fs from 'fs'
import path from 'path'

const REPORT_DIR = path.join(__dirname, '../../reports')

export const downloadReport = () => ({ params }: Request, res: Response) => {
  const name = path.basename(params.name)
  fs.createReadStream(path.join(REPORT_DIR, name)).pipe(res)
}

export function listReports ({ query }: Request, res: Response) {
  const files = fs.readdirSync(REPORT_DIR)
  res.json(files.slice(0, Number(query.limit) || 20))
}

export function buildIndex (body: string, query: { dir: string }) {
  // a plain function whose second parameter happens to be called query
  return fs.readFileSync(path.join(REPORT_DIR, 'index.json'), 'utf8') + body
}
