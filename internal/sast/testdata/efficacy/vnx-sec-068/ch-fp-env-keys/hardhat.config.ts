import { HardhatUserConfig } from "hardhat/config";
import { ethers } from "ethers";

const wallet = new ethers.Wallet(process.env.DEPLOYER_KEY!, new ethers.JsonRpcProvider(process.env.RPC));

const config: HardhatUserConfig = {
  networks: {
    mainnet: {
      url: process.env.MAINNET_RPC || "",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
    base: { url: process.env.BASE_RPC || "", accounts: [`0x${process.env.BASE_PRIVATE_KEY}`] },
  },
};
export default config;
