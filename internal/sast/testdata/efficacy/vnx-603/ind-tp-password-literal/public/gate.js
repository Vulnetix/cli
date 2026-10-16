const btn = document.querySelector('#unlock');
btn.addEventListener('click', () => {
  const password = document.getElementById('pass').value;
~>  if (password === 'S3cretPass!') {
    document.getElementById('content').style.display = 'block';
  }
});
