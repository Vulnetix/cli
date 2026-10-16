export function requireSession(req) {
  const token = req.cookies.session;
  if (!token || !sessions.has(token)) {
    throw new Error(token ? 'session token rejected' : 'session token missing');
  }
  return sessions.get(token);
}
