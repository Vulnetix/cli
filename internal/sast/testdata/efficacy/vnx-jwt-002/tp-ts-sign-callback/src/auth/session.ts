import jwt from 'jsonwebtoken'

export function createSession (userId: string, key: string): Promise<string> {
  return new Promise((resolve, reject) => {
~>    jwt.sign({ userId }, key, (err: Error | null, token?: string) => {
      if (err) reject(err)
      else resolve(token as string)
    })
  })
}
