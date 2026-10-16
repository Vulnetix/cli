const form = document.getElementById('signup');
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = form.password.value;
  const passwordRepeat = form.passwordRepeat.value;
  await fetch('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password, passwordRepeat }),
  });
});
// server reads req.body.passwordRepeat elsewhere
