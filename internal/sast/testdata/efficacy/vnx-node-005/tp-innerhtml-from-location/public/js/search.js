const params = new URLSearchParams(window.location.search);
const term = params.get('q');
~>document.getElementById('results-title').innerHTML = term;
~>banner.innerHTML = decodeURIComponent(location.hash.slice(1));
