import expressJwt from 'express-jwt'
import { Response } from 'express'

~>export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)

export function generateApiKey (): string {
~>  return `key_${Math.random().toString(36).substring(2)}`
}

export function startSession (res: Response): void {
~>  const raw = Math.random().toString(36)
  res.cookie('session_id', raw, { httpOnly: true })
}
