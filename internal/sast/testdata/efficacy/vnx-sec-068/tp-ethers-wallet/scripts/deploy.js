const { ethers } = require("ethers");

const provider = new ethers.JsonRpcProvider("https://mainnet.infura.io/v3/" + process.env.INFURA_ID);
~>const wallet = new ethers.Wallet("0x@@sample:[0-9a-f]{64}@@", provider);
