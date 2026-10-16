// Shapes VNX-NODE-012 used to report too in a JavaScript file; VNX-NODE-005 owns them.
export function Entry({ entry }) {
~>  return <article dangerouslySetInnerHTML={{ __html: entry.body }} />;
}

export function backLink() {
~>  document.write('<p>From ' + document.referrer + '</p>');
}

export function addRow(table, cells) {
  const row = '<tr><td>' + cells.join('</td><td>') + '</td></tr>';
~>  table.insertAdjacentHTML('beforeend', row);
}

export function linkTo(q) {
~>  document.write('<a href="/s?q=' + encodeURIComponent(q) + '">' + q + '</a>');
}

export function legacy(box) {
~>  box.insertAdjacentHTML('afterbegin', '<b>' + unescape(location.search.slice(3)) + '</b>');
}

export function encodedOnly(box, q) {
  document.write('<a href="/s?q=' + encodeURIComponent(q) + '">search</a>');
  box.insertAdjacentHTML('beforeend', DOMPurify.sanitize(q));
}
