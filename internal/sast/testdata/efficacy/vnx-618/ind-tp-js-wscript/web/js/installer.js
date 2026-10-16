function runInstaller(path) {
  try {
~>    var sh = new ActiveXObject("WScript.Shell");
    sh.Run('"' + path + '" /silent', 1, true);
  } catch (e) {
    window.status = "install failed";
  }
}
