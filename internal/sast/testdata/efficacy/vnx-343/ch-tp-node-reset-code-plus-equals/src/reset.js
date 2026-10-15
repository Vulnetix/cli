let resetCode = 482910;

function nextResetCode() {
~>  resetCode += Math.floor(Math.random() * 100);
  return resetCode;
}

module.exports = { nextResetCode };
