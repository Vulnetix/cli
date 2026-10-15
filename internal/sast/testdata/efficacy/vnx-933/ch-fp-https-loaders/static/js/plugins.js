function loadCharts(done) {
  $.getScript("https://charts.example-cdn.com/v2/charts.min.js", done);
  importScripts('/static/js/sjcl.js');
  fetch("http://api.example.com/v1/items").then(function (r) { return r.json(); });
  var s = document.createElement("script");
  var img = document.createElement("img");
  img.src = "http://images.example.com/a.png";
  s.src = "https://widgets.example.com/w.js";
  document.head.appendChild(s);
}
