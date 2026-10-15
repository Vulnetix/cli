import fs from 'fs'
import { pipeline } from 'stream/promises'
import unzipper from 'unzipper'

const MAX_TOTAL = 50 * 1024 * 1024

export async function importArchive (buffer: Buffer, dest: string) {
  const dir = await unzipper.Open.buffer(buffer)
  const total = dir.files.reduce((n, e) => n + e.uncompressedSize, 0)
  if (total > MAX_TOTAL) throw new Error('archive too large')
  for (const entry of dir.files) {
    await pipeline(entry.stream(), fs.createWriteStream(`${dest}/${entry.path.replace(/[\\/]/g, '_')}`))
  }
}
