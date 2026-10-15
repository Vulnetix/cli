const path = require('path');

function ok(file) {
  const ext = path.extname(file.originalname).toLowerCase();
  if (/\.(jpg|png)$/i.test(file.originalname)) return true;
  const last = file.originalname.split('.').pop();
  const type = fileName.substring(fileName.lastIndexOf('.') + 1);
  const payload = token.split('.')[1];
  return ['.jpg', '.png'].includes(ext) && last && type && payload;
}
module.exports = ok;
