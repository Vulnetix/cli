const fs = require("fs");

function mirror(src, dest) {
  const st = fs.lstatSync(src);
  if (st.isSymbolicLink()) {
    return;
  }
  const data = fs.readFileSync(dest + ".prev");
  fs.writeFileSync(dest, data);
}
