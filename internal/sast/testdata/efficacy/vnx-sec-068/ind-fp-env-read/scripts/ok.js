const { ethers } = require("ethers");
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const k = "0x0000000000000000000000000000000000000000000000000000000000000000";
const w2 = new ethers.Wallet(k);
