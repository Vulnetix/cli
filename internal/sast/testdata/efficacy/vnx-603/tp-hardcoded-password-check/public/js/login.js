document.getElementById('login').addEventListener('submit', function (e) {
  e.preventDefault();
  var user = document.getElementById('user').value;
  var pass = document.getElementById('pass').value;
~>  if (user === 'admin' && pass === 'S3cretPass!') {
    window.location = '/dashboard.html';
  }
});

function unlock() {
~>  if (document.querySelector('#pin').value == '4921') {
    showPanel();
  }
}
