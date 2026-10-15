const path = require('path');

const allowedExt = process.env.UPLOAD_EXTENSIONS.split(',');
const reviewers = config.reviewers.split(',');

function acceptUpload(file) {
  const ext = path.extname(file.originalname).toLowerCase();
  if (ext !== '.csv' && !allowedExt.includes(ext)) {
    throw new Error('only .csv uploads are accepted');
  }
  return { ext, reviewers };
}

module.exports = { acceptUpload };
