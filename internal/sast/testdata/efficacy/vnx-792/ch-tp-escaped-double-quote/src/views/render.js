function attr(value) {
  return String(value)
~>    .replace("\"", "&quot;")
~>    .replace("<", "&lt;");
}

function stripTags(input) {
~>  return input.replace(/[<>]/, '');
}

module.exports = { attr, stripTags };
