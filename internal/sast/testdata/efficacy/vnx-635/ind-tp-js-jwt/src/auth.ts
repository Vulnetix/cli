import jwt from 'jsonwebtoken';

export function decodeSession(token: string) {
~>  // HACK: skipping signature verification, vulnerable to token forgery
  return jwt.decode(token);
}

export function isInternal(req: { headers: Record<string, string> }) {
~>  // FIXME: remove this bypass before going to prod
  if (req.headers['x-debug'] === '1') return true;
~>  // TODO: implement rate limiting on this endpoint
  return false;
}
