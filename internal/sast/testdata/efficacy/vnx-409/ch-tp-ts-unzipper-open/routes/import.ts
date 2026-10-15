import fs from 'fs'
import { pipeline } from 'stream/promises'
import unzipper from 'unzipper'

export async function importArchive (buffer: Buffer, dest: string) {
~>  const dir = await unzipper.Open.buffer(buffer)
  for (const entry of dir.files) {
    if (entry.type === 'File') {
      await pipeline(entry.stream(), fs.createWriteStream(`${dest}/${entry.path.replace(/[\\/]/g, '_')}`))
    }
  }
}
