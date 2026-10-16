function createRequest() {
  if (window.XMLHttpRequest) return new XMLHttpRequest();
  try { return new ActiveXObject("Msxml2.XMLHTTP"); } catch (e) {}
  try { return new ActiveXObject("Microsoft.XMLHTTP"); } catch (e) {}
  return null;
}
function parseXml(text) {
  var doc = new ActiveXObject("Microsoft.XMLDOM");
  doc.async = false;
  doc.loadXML(text);
  return doc;
}
