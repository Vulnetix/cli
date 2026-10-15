export async function verifyHCaptcha(token: string): Promise<boolean> {
  const r = await fetch('https://api.hcaptcha.com/siteverify', {
    method: 'POST',
    body: new URLSearchParams({ secret: process.env.HCAPTCHA_SECRET!, response: token }),
  });
  const data = await r.json();
  return data.success === true;
}
