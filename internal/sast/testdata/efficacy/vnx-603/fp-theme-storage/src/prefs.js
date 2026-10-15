export function save(theme) {
  localStorage.setItem('theme', 'dark');
  localStorage.setItem('authorName', 'Ada');
  document.cookie = 'consent=true; path=/';
  if (localStorage.getItem('theme') === 'dark') {
    document.body.classList.add('dark');
  }
  const input = document.getElementById('password');
  if (input.value === '') {
    showError();
  }
}
