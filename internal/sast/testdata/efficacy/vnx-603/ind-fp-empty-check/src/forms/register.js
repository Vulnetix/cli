const form = document.getElementById('register');

form.addEventListener('submit', (e) => {
  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirm').value;
  if (password === '' || password.length < 12) {
    e.preventDefault();
    document.getElementById('hint').textContent = 'Use at least 12 characters';
  }
  if (password !== confirmPassword) {
    e.preventDefault();
  }
});
