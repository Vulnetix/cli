const out = document.getElementById('out');
~>out.innerHTML = location.hash.slice(1);

const params = new URLSearchParams(window.location.search);
const q = params.get('q');
const results = document.querySelector('#results');
~>results.innerHTML = 'You searched for ' + q;

~>document.write("<p>Came from " + document.referrer + "</p>");

window.addEventListener('message', (event) => {
~>  document.getElementById('inbox').outerHTML = event.data;
});
