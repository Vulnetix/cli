const fs = require('fs');
for (const file of fs.readdirSync('./views')) {
  if (file.endsWith('.html')) {
    console.log(file);
  }
}
