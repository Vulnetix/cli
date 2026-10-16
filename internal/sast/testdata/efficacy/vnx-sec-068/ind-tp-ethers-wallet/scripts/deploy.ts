import { ethers } from "ethers";
const provider = new ethers.JsonRpcProvider(process.env.RPC);
~>const wallet = new ethers.Wallet("0x@@sample:[a-f0-9]{64}@@", provider);
