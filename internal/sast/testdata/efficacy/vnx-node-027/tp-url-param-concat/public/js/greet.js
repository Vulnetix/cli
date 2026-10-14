const params = new URLSearchParams(window.location.search);
const name = params.get('name');
~>document.getElementById('greeting').innerHTML = 'Hello, ' + name;
