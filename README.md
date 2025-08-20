# BLS verification in Solidity

[![Solidity ^0.8.x](https://img.shields.io/badge/Solidity-%5E0.8.x-blue)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Foundry Tests](https://img.shields.io/badge/Tested%20with-Foundry-red)](https://book.getfoundry.sh/)

**Experimental, unaudited cryptographic code. Use at your own risk.**

This repository contains Solidity libraries for verifying BLS and threshold BLS signatures.
It supports the BN254 curve, as well as the BLS12-381 curve provided the EIP-2537 precompiles are available.
Point compression is also supported on BLS12-381 G1.

## Structure

```
├── README.md
│   this file
├── src
│   ├── demos
│   │   ├── EvmnetRegistry.sol
│   │   │   permissionlessly verify drand evmnet signatures and store their hash
│   │   └── QuicknetRegistry.sol
│   │       permissionlessly verify drand quicknet signatures and store their hash
│   └── libraries
│       ├── BLS.sol
│       │   BLS verification for BN254
│       │   based on Kevin Charm's bls-bn254 library
│       └── BLS2.sol
│           BLS verification for BLS12-381
│           point compression on G1
├── script
│   ├── DeployEvmnetRegistry.s.sol
│   │   deploy EvmnetRegistry to 0xbF73df94D5F3bf7B19e96Deb613434a9ca106C09
│   │   using Arachnid's permissionless deterministic deployment proxy
│   └── DeployQuicknetRegistry.s.sol
│       deploy QuicknetRegistry to 0xA50970f475F530fa9A93E0C55ebAFef588b07cE3
│       using Arachnid's permissionless deterministic deployment proxy
└── test
    ├── BLS2Test.sol
    ├── BLSTest.sol
    └── data
        test vectors generated using arkworks in Rust
        drand quicknet and evmnet samples
        dcipher samples
```


## Licensing

This library is licensed under the MIT License which can be accessed [here](LICENSE).

## Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to improve the code, feel free to open an issue or submit a pull request.

## Acknowledgments

Huge thanks to Kevin Charm for his work on [bls-bn254](https://github.com/kevincharm/bls-bn254) which was the basis for this library.
