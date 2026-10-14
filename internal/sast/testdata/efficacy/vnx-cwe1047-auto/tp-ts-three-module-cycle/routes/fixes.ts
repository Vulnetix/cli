import * as challenges from '../lib/challenges'

export function readFixes (key: string): string[] {
  challenges.solveIf(key)
  return [key]
}
