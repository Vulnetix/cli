const output = document.getElementById('out');
output.innerHTML = '';
output.innerHTML = '<span class="spinner"></span>';
output.innerHTML = "<p>Loading&hellip;</p>";
output.innerHTML = `<ul></ul>`;
toggle.innerHTML = theme === 'dark' ? '&#9728;' : '&#9790;';
price.innerHTML = 2999.99;
output.textContent = 'Hello, ' + name;
if (output.innerHTML === expected) {
  output.innerText = expected;
}
const EMPTY = '<em>none</em>';
output.innerHTML = EMPTY;
