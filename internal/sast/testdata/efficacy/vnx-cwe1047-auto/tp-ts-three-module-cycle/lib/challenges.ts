import * as anti from './anti'

export function solveIf (key: string): void {
  if (anti.cheatScore(key) > 0.9) {
    console.warn('suspicious solve', key)
  }
}
