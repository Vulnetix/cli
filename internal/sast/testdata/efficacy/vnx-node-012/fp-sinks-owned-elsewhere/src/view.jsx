// In a JavaScript file an innerHTML/outerHTML assignment is VNX-NODE-027's,
// and insertAdjacentHTML, document.write and dangerouslySetInnerHTML are
// VNX-NODE-005's; this rule does not report them a second time.
export function View({ post }) {
  return <section dangerouslySetInnerHTML={{ __html: post.body }} />;
}

export function render(out) {
  const q = new URLSearchParams(location.search).get('q');
  out.innerHTML = 'You searched for ' + q;
  out.outerHTML = location.hash.slice(1);
  out.insertAdjacentHTML('beforeend', `<p>${q}</p>`);
  document.write('<p>From ' + document.referrer + '</p>');
}
