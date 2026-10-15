const net = require("net");

module.exports = {
~>  scannerHostName: "192.168.56.20",
  scannerPort: 8080,
};

async function loadPrices() {
~>  const res = await fetch(`http://10.1.2.30:3000/prices`);
  return res.json();
}

function openFeed() {
~>  return net.connect(5000, "10.1.2.31");
}

module.exports.loadPrices = loadPrices;
module.exports.openFeed = openFeed;
