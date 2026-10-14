import jwt from 'jsonwebtoken'

const key = process.env.JWT_PUBLIC_KEY

export function check(token, cb) {
~>  jwt.verify(token, key, { algorithms: ['RS256', 'none'] }, cb)
}

export function checkSync(token) {
  return jwt.verify(token, key, {
~>    algorithms: ["none"],
    issuer: 'auth.example.com',
  })
}
