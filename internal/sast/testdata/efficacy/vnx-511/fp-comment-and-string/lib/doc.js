// Example of a time bomb: if (new Date() > new Date('2026-01-01')) fs.rmSync(dir)
const EXAMPLE = "if (Date.now() > 1798761600000) fs.rmSync('/')";

function show() {
  console.log(EXAMPLE);
}

module.exports = show;
