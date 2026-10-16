'use strict';
const fs = require('fs');
const path = require('path');

function resolveCurrent(releaseDir) {
  const current = path.join(releaseDir, 'current');
  const st = fs.lstatSync(current);
  if (st.isSymbolicLink()) {
    return fs.readlinkSync(current);
  }
  return null;
}

function removeStaleLink(linkPath) {
  if (fs.lstatSync(linkPath).isSymbolicLink()) {
    fs.unlinkSync(linkPath);
  }
}

module.exports = { resolveCurrent, removeStaleLink };
