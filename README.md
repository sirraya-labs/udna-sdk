# Sirraya Labs UDNA SDK

<div align="center">

**W3C Universal DID-Native Addressing Implementation**

[![PyPI version](https://badge.fury.io/py/sirraya-udna-sdk.svg)](https://badge.fury.io/py/sirraya-udna-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

**Built by [Sirraya Labs](https://sirraya.org) | Compliant with [W3C DID Core](https://www.w3.org/TR/did-core/)**

</div>

## Overview

The Sirraya Labs UDNA SDK provides a production-ready implementation of Universal DID-Native Addressing, enabling:

- Decentralized Identifier (DID) generation and management
- UDNA address creation and cryptographic verification
- Privacy-preserving pairwise DIDs
- Secure key rotation and management

## Features

| Feature | Status | Standard |
|---------|--------|----------|
| did:key method | ✅ Complete | W3C |
| did:web method | 🔄 Planned | W3C |
| UDNA addressing | ✅ Complete | Custom |
| Cryptographic verification | ✅ Complete | Ed25519 |
| Key rotation | ✅ Complete | Custom |
| Pairwise DIDs | ✅ Complete | W3C |
| CLI interface | ✅ Complete | - |

## Installation

```bash
pip install sirraya-udna-sdk


from sirraya_udna import UdnaSDK

# Initialize SDK
sdk = UdnaSDK()

# Create a DID
did = sdk.create_did()
print(f"DID: {did.did}")

# Create a UDNA address
address = sdk.create_address(did.did, flags=["messaging", "routing"])
print(f"Address: {address.address}")

# Verify the address
result = sdk.verify_address(address.address)
print(f"Valid: {result.is_valid}")


# Create identity
sirraya-udna create --flags messaging routing

# Verify address
sirraya-udna verify --address "7XFJXFpgRQ..."

# Get DID info
sirraya-udna info --did "did:key:z6Mkk..."