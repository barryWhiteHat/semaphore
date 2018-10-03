# EthSnarks

Zero-Knowledge proofs are coming to Ethereum and Dapps in 2018/2019!

EthSnarks is a collection of zkSNARK circuits and supporting libraries to use them with Ethereum smart contracts, it aims to help solve one of the biggest problems facing zkSNARKS on Ethereum - cross-platform on desktop, mobile and in-browser, cheap enough to run on-chain, and with algorithms that significantly reduces the time it takes to run the prover.

The notable advantages of using EthSnarks are:

 * Reduced cost, 500k gas with 1 input, using [Groth16](https://eprint.iacr.org/2016/260.pdf).
 * Prove zkSNARKs in-browser, with WebAssembly and Emscripten
 * Linux, Mac and (soon) Windows builds
 * Solidity, Python and C++ support in one place
 * A growing library of gadgets and algorithms

EthSnarks is participating in the Ethereum Foundation's grants program Wave 4, over the next 6-8 months development will continue full-time, and we will be working with companies and developers to help overcome the common challenges and hurdles that we all face. Get in-touch for more information.

**WARNING: EthSnarks is alpha quality software, improvements and fixes are made frequently, and documentation doesn't yet exist**

## Examples

### Miximus

Miximus is a self-service coin mixer and anonymous transfer method for Ethereum, it accepts deposits of 1 ETH, then allows you to withdraw coins by providing a zkSNARK proof that proves you know the spend key for one unspent coin without revealing which one it is.

For more information, see:

 * [Miximus.sol](contracts/Miximus.sol)
 * [miximus.py](ethsnarks/mod/miximus.py)
 * [test_miximus.py](test/test_miximus.py)
 * [miximus.cpp](src/mod/miximus.cpp)

The zkSNARK prover is built as a native library which can plug-in to your application, when provided with the correct arguments it returns the zkSNARK proof as JSON. While you may think of zkSNARKs as being slow - the algorithms chosen for Miximus mean proofs can be made in 5 seconds, however we're still studying their security properties.

## Building

[![Build Status](https://travis-ci.org/HarryR/ethsnarks.svg?branch=master)](https://travis-ci.org/HarryR/ethsnarks) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/137909bd889347728818d0aa5570fa9a)](https://www.codacy.com/project/HarryR/ethsnarks/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=HarryR/ethsnarks&amp;utm_campaign=Badge_Grade_Dashboard) [![BCH compliance](https://bettercodehub.com/edge/badge/HarryR/ethsnarks?branch=master)](https://bettercodehub.com/)

Type `make` - the first time you run it will retrieve submodules, setup cmake and build everything, for more information about the build process see the [Travis-CI build logs](https://travis-ci.org/HarryR/ethsnarks). The following dependencies (for Linux) are needed:

 * cmake
 * g++ or clang++
 * gmp
 * libcrypto
 * boost
 * npm / nvm

WebAssembly and JavaScript builds are supported via [ethsnarks-emscripten](https://github.com/harryr/ethsnarks-emscripten)

# Requests and Contributions

This project aims to help create an ecosystem where a small number of well tested but simple zkSNARK circuits can be easily integrated into your project without having to do all of the work up-front.

If you have any ideas for new components, please [Open an issue](https://github.com/HarryR/ethsnarks/issues/new), or submit a pull request.

# Gadgets

We are surely increasing the range of gadgets, supporting libraries, available documentation and examples; at the moment the best way to find out how to use something is to dig into the code or ask questions via a [new issue](https://github.com/HarryR/ethsnarks/issues/new?labels=question,help%20wanted)

The following gadgets are available

 * 1-of-N
 * [MiMC](https://eprint.iacr.org/2016/492) / LongsightL cipher
 * [Miyaguchi-Preneel one-way function](https://en.wikipedia.org/wiki/One-way_compression_function)
 * 'Field-native' Merkle tree
 * SHA256 (Ethereum compatible, full round)
 * [Shamir's Secret Sharing Scheme](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
 * 'Baby JubJub' twisted Edwards curve
   * EdDSA
   * Pedersen commitments

## Maintainers

[@HarryR](https://github.com/HarryR)
