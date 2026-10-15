function clean(p) {
~>  return p.replace(/\.\.\//, '');
}

function noSub(cmd) {
~>  return cmd.replace(/\$\(/, '');
}
