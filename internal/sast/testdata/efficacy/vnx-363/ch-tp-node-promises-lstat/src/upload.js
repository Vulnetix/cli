const fs = require("fs");

async function storeUpload(target, body) {
  const st = await fs.promises.lstat(target);
  if (st.isSymbolicLink()) {
    throw new Error("symlink");
  }
~>  await fs.promises.writeFile(target, body);
}

module.exports = { storeUpload };
