const fs = require('fs');

function save(file, text) {
  const st = fs.lstatSync(file);
  if (st.isSymbolicLink()) {
    throw new Error('symlink');
  }
~>  fs.writeFileSync(file, text);
}

async function saveAsync(file, text) {
  if (!(await fs.promises.lstat(file)).isSymbolicLink()) {
~>    await fs.promises.writeFile(file, text);
  }
}

module.exports = { save, saveAsync };
