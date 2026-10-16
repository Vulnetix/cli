const path = require('path');

function check(file) {
  const ext = path.extname(file.originalname).toLowerCase();
  const alt = file.originalname.split('.').pop();
  const last = file.originalname.slice(file.originalname.lastIndexOf('.'));
  return /\.(png|jpg)$/i.test(file.originalname) && ['.png', '.jpg'].includes(ext);
}
module.exports = check;
