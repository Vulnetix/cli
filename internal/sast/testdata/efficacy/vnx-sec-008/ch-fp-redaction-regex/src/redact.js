const CREDENTIALS_IN_URL = /(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/([^:]+):([^@]+)@/g;

function redact(url) {
  return url.replace(CREDENTIALS_IN_URL, "$1://$2:***@");
}
module.exports = { redact };
