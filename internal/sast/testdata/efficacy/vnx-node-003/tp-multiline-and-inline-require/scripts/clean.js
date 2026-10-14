const {
  execSync,
} = require("child_process");

function clean(dir) {
~>  execSync(
    "rm -rf " + dir
  );
~>  require('child_process').exec('ls -la ' + dir);
}
module.exports = clean;
