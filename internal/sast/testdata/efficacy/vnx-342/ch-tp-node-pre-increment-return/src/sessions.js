let lastSessionId = 1000;

function newSessionId() {
~>  return ++lastSessionId;
}

module.exports = { newSessionId };
