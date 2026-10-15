const HDWalletProvider = require("@truffle/hdwallet-provider");

module.exports = {
  networks: {
    sepolia: {
~>      provider: () => new HDWalletProvider("@@sample:[0-9a-f]{64}@@", "https://sepolia.infura.io/v3/" + process.env.INFURA_ID),
      network_id: 11155111,
    },
    goerli: {
      provider: () => new HDWalletProvider({
~>        privateKeys: ["0x@@sample:[0-9a-f]{64}@@"],
        providerOrUrl: process.env.GOERLI_RPC,
      }),
      network_id: 5,
    },
  },
};
