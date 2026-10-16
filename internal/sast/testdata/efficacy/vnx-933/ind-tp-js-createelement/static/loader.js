function loadWidget() {
  var el = document.createElement("script");
  el.async = true;
~>  el.src = "http://widgets.example.com/w.js";
  document.head.appendChild(el);
}

~>$.getScript("http://api.example.com/plugin.js");
