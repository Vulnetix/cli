function safeName(name) {
~>  const stripped = name.replaceAll('../', '');
  return stripped;
}
module.exports = { safeName };
