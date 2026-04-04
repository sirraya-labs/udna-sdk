
# Sirraya Labs UDNA SDK

<div align="center">

**W3C Universal DID-Native Addressing Implementation**

[![PyPI version](https://badge.fury.io/py/sirraya-udna-sdk.svg)](https://badge.fury.io/py/sirraya-udna-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

**Built by [Sirraya Labs](https://sirraya.org) | Compliant with [W3C DID Core](https://www.w3.org/TR/did-core/)**

</div>

---

## Overview

The Sirraya Labs UDNA SDK provides a production-ready implementation of Universal DID-Native Addressing, enabling decentralized identity management and secure communication.

### Key Capabilities

- Decentralized Identifier (DID) generation and management
- UDNA address creation and cryptographic verification
- Privacy-preserving pairwise DIDs
- Secure key rotation and management
- Command-line interface for automation

---

## Installation

```bash
pip install sirraya-udna-sdk
```

### Requirements

- Python 3.7 or higher
- cryptography >= 41.0.0
- base58 >= 2.1.0

---

## Quick Start

### Python API

```python
from udna_sdk import UdnaSDK

# Initialize SDK
sdk = UdnaSDK()

# Create a DID
did = sdk.create_did()
print(f"DID: {did.did}")

# Create a UDNA address
address = sdk.create_address(
    did.did, 
    flags=["messaging", "routing"]
)
print(f"Address: {address.address}")

# Verify the address
result = sdk.verify_address(address.address)
print(f"Valid: {result.is_valid}")
```

### Command Line Interface

```bash
# Create a new identity
udna create --flags messaging routing

# Verify an address
udna verify --address "7XFJXFpgRQ..."

# Get DID information
udna info --did "did:key:z6Mkk..."
```

---

## API Reference

### UdnaSDK Class

The main entry point for all UDNA operations.

#### Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `create_did()` | Generates a new DID using the `did:key` method | `DidInfo` |
| `create_address(did, facet_id=0x02, flags=None)` | Creates a UDNA address for a DID | `UdnaAddressInfo` |
| `verify_address(address)` | Cryptographically verifies a UDNA address | `VerificationResult` |

#### Example with Flags

```python
from udna_sdk import UdnaSDK

sdk = UdnaSDK()
did = sdk.create_did()

# Available flags: messaging, routing, ephemeral, priority, encrypted
address = sdk.create_address(
    did.did,
    facet_id=0x02,                      # Messaging facet
    flags=["messaging", "routing"]      # Enable messaging and routing
)

result = sdk.verify_address(address.address)
print(f"Verification passed: {result.is_valid}")
```

### Data Models

#### DidInfo

| Attribute | Type | Description |
|-----------|------|-------------|
| `did` | str | Full DID string |
| `method` | str | DID method (e.g., "key") |
| `identifier` | str | Method-specific identifier |
| `created_at` | str | ISO timestamp of creation |

#### UdnaAddressInfo

| Attribute | Type | Description |
|-----------|------|-------------|
| `address` | str | Base58-encoded UDNA address |
| `did` | str | Associated DID |
| `facet_id` | int | Service facet identifier |
| `flags` | List[str] | Enabled address flags |
| `nonce` | int | 64-bit random nonce |
| `created_at` | str | ISO timestamp of creation |

#### VerificationResult

| Attribute | Type | Description |
|-----------|------|-------------|
| `is_valid` | bool | True if signature verifies |
| `address` | str | The verified address |
| `did` | str | DID from the address |
| `verified_at` | str | ISO timestamp of verification |
| `error` | str or None | Error message if verification failed |

---

## Address Flags

Flags control address behavior and capabilities.

| Flag | Value | Description |
|------|-------|-------------|
| `messaging` | 1 | Enables messaging capabilities |
| `routing` | 2 | Enables routing hints |
| `ephemeral` | 4 | Address is temporary |
| `priority` | 8 | High priority handling |
| `encrypted` | 16 | Encryption enabled |

**Usage:**
```python
address = sdk.create_address(
    did.did,
    flags=["messaging", "routing", "priority"]
)
```

---

## Facet IDs

Facets represent different service types.

| Facet ID | Service Type | Description |
|----------|--------------|-------------|
| 0x01 | Control | Management and configuration |
| 0x02 | Messaging | Communication services |
| 0x03 | Telemetry | Monitoring and analytics |

---

## Command Line Interface

### Commands

#### Create Identity

```bash
udna create [--facet FACET] [--flags FLAGS...] [--output FILE] [--format json]

# Examples
udna create
udna create --facet 0x02 --flags messaging routing
udna create --format json
udna create --output identity.json
```

#### Verify Address

```bash
udna verify --address ADDRESS [--format json]
udna verify --file FILE [--format json]

# Examples
udna verify --address "7XFJXFpgRQ..."
udna verify --file identity.json
```

#### Get Information

```bash
udna info --did DID
udna info --address ADDRESS

# Examples
udna info --did "did:key:z6Mkk..."
udna info --address "7XFJXFpgRQ..."
```

### JSON Output

All commands support `--format json` for script integration:

```bash
$ udna create --format json
{
  "did": {
    "did": "did:key:z6Mkk...",
    "method": "key",
    "identifier": "z6Mkk...",
    "created_at": "2026-04-04T16:42:17.782540"
  },
  "address": {
    "address": "7XFJXFpgRQ...",
    "did": "did:key:z6Mkk...",
    "facet_id": 2,
    "flags": ["messaging", "routing"],
    "nonce": 252016976580823665,
    "created_at": "2026-04-04T16:42:17.782540"
  }
}
```

---

## Programmatic Examples

### Batch Identity Creation

```python
from udna_sdk import UdnaSDK

sdk = UdnaSDK()
identities = []

for i in range(10):
    did = sdk.create_did()
    address = sdk.create_address(did.did, flags=["messaging"])
    identities.append({
        "index": i,
        "did": did.did,
        "address": address.address
    })
```

### Verification with Error Handling

```python
from udna_sdk import UdnaSDK

sdk = UdnaSDK()
result = sdk.verify_address(address_string)

if result.is_valid:
    print(f"Address belongs to DID: {result.did}")
else:
    print(f"Verification failed: {result.error}")
```

### Custom Facet Configuration

```python
from udna_sdk import UdnaSDK

sdk = UdnaSDK()
did = sdk.create_did()

# Control facet (0x01)
control_address = sdk.create_address(did.did, facet_id=0x01)

# Messaging facet (0x02)
messaging_address = sdk.create_address(
    did.did, 
    facet_id=0x02,
    flags=["messaging", "routing"]
)

# Telemetry facet (0x03)
telemetry_address = sdk.create_address(did.did, facet_id=0x03)
```

---

## Architecture

The SDK implements the following specifications:

- **W3C DID Core 1.0** - Decentralized Identifier specification
- **did:key Method** - Cryptographic key-based DIDs
- **Ed25519** - Digital signatures for authentication
- **Base58** - Encoding for addresses and keys

### Address Structure

A UDNA address is a binary structure containing:

```
[Version][DID Type][DID Length][DID][Key Hint][Route Hint][Flags][Nonce][Signature]
```

- **Version**: Protocol version (1)
- **DID Type**: Method identifier (0x01 for did:key)
- **DID**: Full DID string
- **Facet ID**: Service type identifier
- **Flags**: Behavioral flags bitmask
- **Nonce**: 64-bit random value for uniqueness
- **Signature**: Ed25519 signature proving ownership

---

## Security

### Key Management

Private keys are stored in memory only during SDK instance lifetime. For persistent storage, export and secure keys using your own key management system.

```python
# Export private key (for secure storage)
private_key_export = sdk.export_private_key(did.did, format="pem")
# Store securely, not in code
```

### Verification

All UDNA addresses are cryptographically signed. The SDK automatically verifies signatures using the public key from the DID document.

---

## Development

### Local Development Setup

```bash
git clone https://github.com/sirrayalabs/udna-sdk
cd udna-sdk
pip install -e .
```

### Running Tests

```bash
pip install pytest
pytest tests/
```

### Building Documentation

```bash
pip install sphinx
cd docs
make html
```

---

## License

MIT License - Copyright (c) 2026 Sirraya Labs

See [LICENSE](LICENSE) file for details.

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

---

## Support

- **Documentation**: [https://docs.sirraya.org/udna-sdk](https://docs.sirraya.org/udna-sdk)
- **Issues**: [GitHub Issues](https://github.com/sirrayalabs/udna-sdk/issues)
- **Email**: [udna@sirraya.org](mailto:udna@sirraya.org)

---

## Acknowledgments

- W3C DID Working Group for the DID Core specification
- Decentralized Identity Foundation (DIF) for standards guidance
- Python cryptography team for Ed25519 implementation

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-04 | Initial release |
| 1.0.1 | 2026-04-04 | Fix imports, add AddressFlags |
| 1.0.2 | 2026-04-04 | Production ready release |

---

## Citation

If you use this SDK in research or production, please cite:

```bibtex
@software{sirraya_udna_sdk_2026,
  title = {Sirraya Labs UDNA SDK},
  author = {Sirraya Labs},
  year = {2026},
  url = {https://github.com/sirrayalabs/udna-sdk},
  note = {W3C Universal DID-Native Addressing Implementation}
}
```

---

**Built by [Sirraya Labs](https://sirraya.org) | W3C Compliant | MIT Licensed**
```

