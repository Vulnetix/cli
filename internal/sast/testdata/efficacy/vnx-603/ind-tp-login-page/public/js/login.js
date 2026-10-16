const form = document.querySelector('#login-form');

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const user = document.getElementById('username').value;
  const password = document.getElementById('password').value;
~>  if (user === 'admin' && password === 'Winter2024!') {
~>    localStorage.setItem('isLoggedIn', 'true');
    window.location.href = '/dashboard.html';
  } else {
    document.getElementById('error').textContent = 'Invalid credentials';
  }
});
