// Intranet helper used by the IE-only operations console.
function openLogFolder(path) {
~>  var shell = new ActiveXObject("Shell.Application");
  shell.Open(path);
}

function readLocalConfig(name) {
~>  var fso = new ActiveXObject("Scripting.FileSystemObject");
  var f = fso.OpenTextFile("C:\\ops\\" + name, 1);
  var text = f.ReadAll();
  f.Close();
  return text;
}

function restartAgent() {
~>  var wsh = new ActiveXObject('WScript.Shell');
  return wsh.Run("net stop opsagent && net start opsagent", 0, true);
}
