function loadWidget() {
  var s = document.createElement('script');
~>  s.src = 'http://widgets.example-chat.com/embed.js';
  document.head.appendChild(s);
}

function loadPixel() {
  const tag = document.createElement("script");
  tag.async = true;
~>  tag.setAttribute("src", "http://pixel.example-ads.net/p.js");
  document.body.appendChild(tag);
}
