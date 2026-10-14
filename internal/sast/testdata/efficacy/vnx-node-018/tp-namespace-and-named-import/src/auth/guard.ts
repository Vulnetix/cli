import * as jsonwebtoken from 'jsonwebtoken'
import { decode as readToken, JwtPayload } from "jsonwebtoken"

export function currentUser(token: string): string | undefined {
~>  const decoded = jsonwebtoken.decode(token, { complete: true })
  return (decoded?.payload as JwtPayload)?.sub
}

export function isAdmin(token: string): boolean {
~>  const payload = readToken(
    token,
  ) as JwtPayload
  return payload?.role === 'admin'
}
