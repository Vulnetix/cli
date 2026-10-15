import { Router } from 'express'
import multer from 'multer'
import path from 'path'
import fs from 'fs'

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5_000_000 } })
const PUBLIC_DIR = path.resolve(__dirname, '../../public/photos')
export const photos = Router()

photos.post('/me/photo', upload.single('photo'), async (req, res) => {
  const picked = req.file
  if (!picked || !picked.mimetype.startsWith('image/')) {
    return res.status(415).json({ error: 'unsupported' })
  }
  const target = path.join(PUBLIC_DIR, `${req.user.id}.jpg`)
~>  await fs.promises.writeFile(target, picked.buffer)
  res.json({ url: `/photos/${req.user.id}.jpg` })
})
