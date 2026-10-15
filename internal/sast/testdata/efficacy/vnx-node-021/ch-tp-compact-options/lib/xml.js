var libxmljs = require("libxmljs");

exports.parse = function (xml) {
~>  return libxmljs.parseXml(xml, {noent:true,noblanks:true});
};
