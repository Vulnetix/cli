// Collects inline script bodies from a fetched page for the bundle analyser.
function inlineScripts(html) {
  const out = [];
  let pos = 0;
  while ((pos = html.indexOf("<script", pos)) !== -1) {
    const end = html.indexOf("</script>", pos);
    if (end === -1) break;
    out.push(html.slice(pos, end));
    pos = end + 9;
  }
  return out;
}

module.exports = { inlineScripts };
