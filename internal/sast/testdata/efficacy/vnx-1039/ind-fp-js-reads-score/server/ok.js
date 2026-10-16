// reCAPTCHA v3: grecaptcha.execute on the client
async function verify(token) {
  const resp = await fetch('https://www.google.com/recaptcha/api/siteverify', { method: 'POST', body: `secret=${process.env.RECAPTCHA_V3_SECRET}&response=${token}` });
  const { success, score } = await resp.json();
  return success && score >= 0.5;
}
