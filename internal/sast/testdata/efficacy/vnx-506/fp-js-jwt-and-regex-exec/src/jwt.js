const PART = /^([^.]+)\.([^.]+)\.([^.]+)$/;

export function claims(token) {
  const m = PART.exec(atob(token));
  const payload = JSON.parse(atob(token.split('.')[1]));
  const raw = Buffer.from(token, 'base64').toString();
  return { m, payload, raw };
}
