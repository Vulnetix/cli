let prevCode = 100000;

function nextConfirmationCode() {
~>  const confirmationCode = prevCode + Math.floor(Math.random() * 100);
  prevCode = confirmationCode;
  return String(confirmationCode);
}

module.exports = { nextConfirmationCode };
