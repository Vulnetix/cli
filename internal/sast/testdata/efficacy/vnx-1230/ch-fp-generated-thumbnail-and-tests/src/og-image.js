const fs = require('fs');
const { createCanvas } = require('canvas');

function renderOgImage(title, outPath) {
  const canvas = createCanvas(1200, 630);
  const ctx = canvas.getContext('2d');
  ctx.fillText(title, 40, 300);
  fs.writeFileSync(outPath, canvas.toBuffer('image/png'));
}

module.exports = { renderOgImage };
