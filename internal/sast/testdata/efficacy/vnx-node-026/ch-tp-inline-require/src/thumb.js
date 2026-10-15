function thumbnail(src) {
~>  return require('child_process').spawn(`convert ${src} -resize 64x64 out.png`, { shell: true });
}
module.exports = thumbnail;
