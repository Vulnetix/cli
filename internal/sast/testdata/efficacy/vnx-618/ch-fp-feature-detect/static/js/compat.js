function createXhr() {
  if (window.ActiveXObject) {
    try {
      return new ActiveXObject("Msxml2.XMLHTTP.6.0");
    } catch (e) {
      return new ActiveXObject("Microsoft.XMLHTTP");
    }
  }
  return new XMLHttpRequest();
}

function parseXml(text) {
  var doc = new ActiveXObject('@@sample:M[s]xm[l]2[.][D]OM[D]oc[u]me[n]t[.][6][.]0@@');
  doc.loadXML(text);
  return doc;
}

var hint = "Do not use new ActiveXObject(\"WScript.Shell\") in this app";
console.warn(`CreateObject("Shell.Application") is blocked by policy`);
