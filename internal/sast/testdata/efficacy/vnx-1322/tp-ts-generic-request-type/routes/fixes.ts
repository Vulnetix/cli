import fs from 'fs'
import yaml from 'js-yaml'
import { type Request, type Response, type NextFunction } from 'express'

interface Body { key: string }

export const explain = () => async (req: Request<Record<string, unknown>, unknown, Body>, res: Response, next: NextFunction) => {
  const key = req.body.key.replace(/[^a-z]/g, '')
  const file = `./data/fixes/${key}.yml`
~>  if (fs.existsSync(file)) {
~>    res.json(yaml.load(fs.readFileSync(file, 'utf8')))
  } else {
    next()
  }
}
