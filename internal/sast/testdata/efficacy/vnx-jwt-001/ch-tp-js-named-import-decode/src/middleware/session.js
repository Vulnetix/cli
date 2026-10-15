import { decode } from 'jsonwebtoken';

export function session(req, res, next) {
~>  const claims = decode(req.cookies.session);
  if (!claims) return res.sendStatus(401);
  req.user = claims;
  next();
}
