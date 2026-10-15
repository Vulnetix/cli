import { HardhatUserConfig } from "hardhat/config";

const config: HardhatUserConfig = {
  networks: {
    mainnet: {
      url: "https://eth-mainnet.g.alchemy.com/v2/demo",
~>      accounts: ["0x@@sample:[0-9a-f]{64}@@"],
    },
  },
};
export default config;
