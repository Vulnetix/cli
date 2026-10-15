const NON_ALNUM = /[^a-z0-9]/i

function strongEnough (pw) {
  if (!/[A-Z]/.test(pw)) return false
  if (!/[0-9]+/.test(pw)) return false
  if (NON_ALNUM.test(pw)) return true
  return /^[a-z0-9]{8,64}$/i.test(pw)
}

function badChars (s) {
  return /[^\w.-]+/.test(s)
}

module.exports = { strongEnough, badChars }
