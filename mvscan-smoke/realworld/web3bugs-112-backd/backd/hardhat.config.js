/**
 * MV-Scan reproduction configuration for Web3Bugs report 112.
 */
module.exports = {
  solidity: {
    version: "0.8.9",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      outputSelection: {
        "*": {
          "*": [
            "abi",
            "metadata",
            "evm.bytecode",
            "evm.deployedBytecode",
            "evm.methodIdentifiers",
            "storageLayout"
          ],
          "": ["ast"]
        }
      }
    }
  }
};
