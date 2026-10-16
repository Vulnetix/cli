require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.24",
  networks: {
    mainnet: {
      url: "https://eth.acme-corp.io/rpc",
~>      accounts: ["0x@@sample:[a-f0-9]{64}@@"],
    },
  },
};
