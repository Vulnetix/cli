function showQuery(q) {
~>  results.innerHTML = '<h2>Results for ' + encodeURIComponent(q) + '</h2>';
}

function showUser(name) {
~>  document.getElementById('who').innerHTML = `<b title='${encodeURI(name)}'>${encodeURI(name)}</b>`;
~>  document.write("<p>" + escape(name) + "</p>");
}
