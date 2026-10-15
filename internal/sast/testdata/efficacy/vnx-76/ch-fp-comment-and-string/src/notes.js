// Never write path.replace("../", "") on its own: ....// rebuilds ../
const HINT = 'a single input.replace("<script>", "") is bypassable';

function explain() {
  return HINT;
}

module.exports = { explain };
