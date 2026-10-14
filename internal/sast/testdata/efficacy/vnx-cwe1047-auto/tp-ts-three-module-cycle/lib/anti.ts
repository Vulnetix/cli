import { createHash } from 'crypto'
~>import { readFixes } from '../routes/fixes'

export function cheatScore (key: string): number {
  const fixes = readFixes(key)
  return createHash('sha256').update(fixes.join()).digest()[0] / 255
}
