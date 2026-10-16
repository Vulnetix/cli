~>window.addEventListener('message', function (event) {
  const data = JSON.parse(event.data);
  document.getElementById('out').innerHTML = data.html;
});
