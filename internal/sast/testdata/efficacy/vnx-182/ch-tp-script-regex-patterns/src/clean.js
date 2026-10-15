export function stripScripts(html) {
~>  return html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
}

export function stripTraversal(p) {
~>  return p.replace(/\.\.[\/\\]/g, "");
}
