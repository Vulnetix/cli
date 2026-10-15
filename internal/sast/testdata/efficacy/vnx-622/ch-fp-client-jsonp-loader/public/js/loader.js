function loadJsonp(endpoint, onData) {
  const cbName = 'jsonp_' + Date.now();
  window[cbName] = function (data) {
    delete window[cbName];
    onData(data);
  };
  const script = document.createElement('script');
  script.src = endpoint + '?callback=' + cbName;
  document.body.appendChild(script);
}

// server example: res.send(req.query.callback + '(' + data + ')')
const help = "res.send(req.query.callback + '(' + data + ')') is unsafe";
