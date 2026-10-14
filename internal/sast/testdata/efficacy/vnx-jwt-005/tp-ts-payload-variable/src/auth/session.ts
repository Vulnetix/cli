import jwt from 'jsonwebtoken'

export function issue (user: User, key: string): string {
  const claims = {
    sub: user.id,
~>    'password': user.password,
    role: user.role,
  }
  return jwt.sign(claims, key, { expiresIn: '15m' })
}
