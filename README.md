# BLS verification in Solidity

[![Solidity ^0.8.x](https://img.shields.io/badge/Solidity-%5E0.8.x-blue)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Foundry Tests](https://img.shields.io/badge/Tested%20with-Foundry-red)](https://book.getfoundry.sh/)

**Experimental, unaudited cryptographic code. Use at your own risk.**

This repository contains Solidity libraries for verifying BLS and threshold BLS signatures.
It supports the BN254 curve, as well as the BLS12-381 curve provided the EIP-2537 precompiles are available.
Point compression is also supported on BLS12-381 G1.

## Licensing

This library is licensed under the MIT License which can be accessed [here](LICENSE).

## Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to improve the code, feel free to open an issue or submit a pull request.

## Acknowledgments

Huge thanks to Kevin Charm for his work on [bls-bn254](https://github.com/kevincharm/bls-bn254) which was the basis for this library.
