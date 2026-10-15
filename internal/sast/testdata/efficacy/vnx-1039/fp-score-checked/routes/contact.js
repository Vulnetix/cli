router.post('/contact', async (req, res) => {
  const resp = await fetch('https://www.google.com/recaptcha/api/siteverify', { method: 'POST', body });
  const data = await resp.json();
  if (!data.success || data.score < 0.5 || data.action !== 'contact') {
    return res.status(403).json({ success: false });
  }
  res.json({ success: true });
});
