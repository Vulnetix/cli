const { fileTypeFromBuffer } = require('file-type');
const path = require('path');
async function check(file) {
  const ext = path.extname(file.originalname).toLowerCase();
  const type = await fileTypeFromBuffer(file.buffer);
  if (!type || !['image/png', 'image/jpeg'].includes(type.mime)) throw new Error('bad');
  return ext;
}
