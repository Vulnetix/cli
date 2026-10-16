import jwt from 'jsonwebtoken';

const privateKey = '@@sample:[-]{5}BEGIN[ ]RSA[ ]PRIVATE[ ]KEY[-]{5}[A-Za-z0-9+/]{64}@@'

export const authorize = (user: object) => jwt.sign(user, privateKey, { algorithm: 'RS256' })
