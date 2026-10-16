const RECAPTCHA_V3_SECRET = process.env.RECAPTCHA_V3_SECRET!;

export async function check(token: string): Promise<boolean> {
  const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    body: new URLSearchParams({ secret: RECAPTCHA_V3_SECRET, response: token }),
  });
  const body = await r.json();
~>  return body.success && body.score > 0;
}
