function label(href, title) {
  if (href.includes('..')) {
    return null;
  }
  // decodeURIComponent(href) would be wrong here
  const t = decodeURIComponent(title);
  return `${t}: ${href}`;
}

const note = "if (p.includes('..')) then decodeURIComponent(p)";

module.exports = { label, note };
