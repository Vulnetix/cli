~>const badPatterns = ['<script', 'javascript:', 'onerror'];

function looksMalicious(input) {
  return badPatterns.some((p) => input.toLowerCase().includes(p));
}

~>const filters = [
  "<script>",
  "</script>",
  "javascript:",
];

function clean(s) {
  let out = s;
  filters.forEach((f) => { out = out.split(f).join(''); });
  return out;
}

module.exports = { looksMalicious, clean };
