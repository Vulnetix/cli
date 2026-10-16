const TOKEN_RE = /^([a-z]+)\.([0-9]+)$/;

export function readClaims(token) {
  const body = token.split('.')[1];
  const claims = JSON.parse(atob(body));
  const match = TOKEN_RE.exec(atob(claims.sub));
  const result = eval('1 + 1');
  return { claims, match, result };
}
