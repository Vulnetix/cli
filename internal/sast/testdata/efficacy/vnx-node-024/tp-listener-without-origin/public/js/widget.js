(function () {
  var output = document.getElementById('output');

~>  window.addEventListener('message', function (event) {
    var msg = event.data;
    if (msg.type === 'render') {
      output.innerHTML = msg.html;
    }
  });
})();
