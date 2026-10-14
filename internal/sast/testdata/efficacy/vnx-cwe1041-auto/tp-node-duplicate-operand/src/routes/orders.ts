import { Router } from 'express'

const router = Router()

router.delete('/orders/:id', (req, res) => {
~>  if (req.user.isAdmin() || req.user.isAdmin()) {
    return res.status(204).end()
  }
  res.status(403).end()
})

function tokenState(token?: string) {
  if (token === undefined) {
    return 'missing'
  } else if (token.length < 16) {
    return 'short'
~>  } else if (token === undefined) {
    return 'unreachable'
  }
  return 'ok'
}

export function guard(req, res, next) {
  verifyCsrfToken(req)
~>  verifyCsrfToken(req)
  next()
}

export default router
