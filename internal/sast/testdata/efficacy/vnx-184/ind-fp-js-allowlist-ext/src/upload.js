const path = require('path');

const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.webp'];

function accept(filename) {
  return ALLOWED_EXTENSIONS.includes(path.extname(filename).toLowerCase());
}

module.exports = { accept };
