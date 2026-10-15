import { Router, Request, Response } from 'express'
import { execSync } from 'child_process'
import { writeFileSync } from 'fs'

export const convert = Router()

convert.post('/convert', async (req: Request, res: Response) => {
  const input = `/tmp/upload-${Date.now()}.docx`
~>  writeFileSync(input, req.body)
~>  const out = execSync(`soffice --headless --convert-to pdf ${input}`)
  res.send(out)
})
