const fs = require('fs');

function store(dir, file, data) {
~>  fs.mkdirSync(dir, { recursive: true, mode: 755 });
~>  fs.writeFileSync(file, data, { mode: 600 });
~>  fs.chmodSync(file, 644);
}
module.exports = { store };
