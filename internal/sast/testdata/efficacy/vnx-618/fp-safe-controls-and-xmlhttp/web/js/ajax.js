function createRequest() {
  if (window.XMLHttpRequest) {
    return new XMLHttpRequest();
  }
  try {
    return new ActiveXObject("Msxml2.XMLHTTP");
  } catch (e) {
    return new ActiveXObject("Microsoft.XMLHTTP");
  }
}

function parseXml(text) {
  var doc = new ActiveXObject("Microsoft.XMLDOM");
  doc.loadXML(text);
  return doc;
}
