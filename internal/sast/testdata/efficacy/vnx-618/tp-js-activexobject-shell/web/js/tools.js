function runTool(name) {
~>  var sh = new ActiveXObject("WScript.Shell");
  sh.Run(name);
}

function saveLocal(path, text) {
~>  var fso = new ActiveXObject('Scripting.FileSystemObject');
  var f = fso.CreateTextFile(path, true);
  f.Write(text);
}

function openFolder() {
~>  var app = new ActiveXObject( "Shell.Application" );
  app.ShellExecute("explorer.exe");
}

function download(url) {
~>  var stream = new ActiveXObject("ADODB.Stream");
}
