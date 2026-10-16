const AdmZip = require('adm-zip');
const path = require('path');

async function installTheme(uploadPath, themesRoot, name) {
  const zip = new AdmZip(uploadPath);
  const dir = path.join(themesRoot, path.basename(name));
~>  zip.extractAllTo(dir, true);
  return dir;
}

module.exports = { installTheme };
