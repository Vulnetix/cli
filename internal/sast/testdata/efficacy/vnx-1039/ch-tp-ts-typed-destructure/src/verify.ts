export async function verifyRecaptcha(token: string): Promise<boolean> {
  const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    body: new URLSearchParams({ secret: process.env.RECAPTCHA_SECRET!, response: token }),
  });
~>  const { success }: { success: boolean } = await r.json();
  return success;
}
