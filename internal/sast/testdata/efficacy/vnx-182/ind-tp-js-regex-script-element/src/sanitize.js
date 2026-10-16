function stripScripts(html) {
~>  return html.replace(/<script[^>]*>.*?<\/script>/gi, '');
}

function stripJsUrls(href) {
~>  return href.replaceAll('javascript:', '');
}

module.exports = { stripScripts, stripJsUrls };
