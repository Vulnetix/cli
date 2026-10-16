document.addEventListener('DOMContentLoaded', () => {
~>  window.addEventListener('message', function (event) {
    document.getElementById('out').innerHTML = event.data.html;
  });
});
