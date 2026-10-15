function isAllowed(user, action) {
  return opa.evaluate({ user, action }).then((r) => r.allow).catch(() => false);
}

function loadPreview(url) {
  return fetch(url).then(() => true).catch(() => true);
}

module.exports = { isAllowed, loadPreview };
