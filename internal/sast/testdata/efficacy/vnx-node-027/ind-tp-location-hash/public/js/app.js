window.addEventListener('hashchange', function () {
  var section = decodeURIComponent(location.hash.slice(1));
  var title = document.querySelector('#title');
~>  title.innerHTML = '<h1>' + section + '</h1>';
});
