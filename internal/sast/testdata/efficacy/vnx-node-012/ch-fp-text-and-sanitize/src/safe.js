import DOMPurify from 'dompurify';

const out = document.getElementById('out');
out.textContent = location.hash.slice(1);
out.innerHTML = DOMPurify.sanitize(new URLSearchParams(location.search).get('q'));
out.innerHTML = '';
const spinner = document.createElement('div');
spinner.innerHTML = '<span class="spinner" aria-hidden="true"></span>';
const current = $('#x').html();
