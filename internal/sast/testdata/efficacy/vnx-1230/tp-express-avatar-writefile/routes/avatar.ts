import fs from 'node:fs/promises'
import { type Request, type Response } from 'express'
import fileType from 'file-type'

export function uploadAvatar () {
  return async (req: Request, res: Response) => {
    const file = req.file
    const buffer = file?.buffer
    if (buffer === undefined) return res.sendStatus(400)
    const kind = await fileType.fromBuffer(buffer)
    if (!kind || !kind.mime.startsWith('image')) return res.sendStatus(415)
    const target = `public/images/avatars/${req.params.id}.${kind.ext}`
~>    await fs.writeFile(target, buffer)
~>    fs.writeFileSync(`public/images/avatars/${req.params.id}-orig.${kind.ext}`, req.file.buffer)
    res.redirect('/profile')
  }
}
