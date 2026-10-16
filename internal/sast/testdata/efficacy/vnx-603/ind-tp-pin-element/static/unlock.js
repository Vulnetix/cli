document.getElementById('unlock').addEventListener('click', function () {
~>  if (document.getElementById('pin').value === '4821') {
    document.getElementById('vault').style.display = 'block';
  } else {
    alert('Wrong PIN');
  }
});
