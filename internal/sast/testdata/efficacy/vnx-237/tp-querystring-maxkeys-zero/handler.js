const querystring = require("querystring");

function onBody(body) {
~>  const fields = querystring.parse(body, "&", "=", { maxKeys: 0 });
  return fields;
}
