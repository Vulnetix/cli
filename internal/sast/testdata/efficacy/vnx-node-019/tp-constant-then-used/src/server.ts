import jwt from 'jsonwebtoken'
import { expressjwt } from 'express-jwt'
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt'
import passport from 'passport'

~>const SIGNING_KEY = 'b2c4e6f8a0-signing'

export function login(userId: string): string {
  return jwt.sign({ sub: userId }, SIGNING_KEY)
}

export const requireAuth = expressjwt({
~>  secret: 'shared-api-secret',
  algorithms: ['HS256'],
})

passport.use(new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
~>  secretOrKey: 'passport-jwt-key',
}, (payload, done) => done(null, payload)))
