export function show(container, html, row) {
~>  container.innerHTML=html;
~>  row.outerHTML += '<td>' + row.dataset.value + '</td>';
}
