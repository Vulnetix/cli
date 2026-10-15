// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";

contract Deploy is Script {
    function run() external {
~>        uint256 deployerPrivateKey = 0x@@sample:[0-9a-f]{64}@@;
        vm.startBroadcast(deployerPrivateKey);
        vm.stopBroadcast();
    }
}
