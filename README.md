
# Sirraya Labs UDNA SDK

<div align="center">

**W3C Universal DID-Native Addressing Implementation**

[![PyPI version](https://badge.fury.io/py/sirraya-udna-sdk.svg)](https://badge.fury.io/py/sirraya-udna-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

**Built by [Sirraya Labs](https://sirraya.org) | Compliant with [W3C DID Core](https://www.w3.org/TR/did-core/)**

</div>

---

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Python API Reference](#python-api-reference)
- [Command Line Interface](#command-line-interface)
- [Advanced Features](#advanced-features)
- [Examples](#examples)
- [Architecture](#architecture)
- [Security](#security)
- [Development](#development)
- [License](#license)

---

## Overview

The Sirraya Labs UDNA SDK provides a production-ready implementation of Universal DID-Native Addressing, enabling decentralized identity management and secure communication.

### Key Capabilities

| Capability | Description | Status |
|------------|-------------|--------|
| DID Generation | Create W3C-compliant DIDs (did:key, did:web) | Complete |
| UDNA Addresses | Generate compact, verifiable network addresses | Complete |
| Cryptographic Verification | Ed25519 signature verification | Complete |
| Key Rotation | Secure key rotation with cryptographic proof | Complete |
| Identity Export/Import | Backup and restore identities | Complete |
| Pairwise DIDs | Relationship-specific privacy DIDs | Complete |
| Secure Messaging | Noise protocol encrypted communication | Complete |
| Storage Directory | Persistent identity storage | Complete |
| CLI Interface | Command-line tools for automation | Complete |
| JSON Output | Script-friendly JSON formatting | Complete |

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

## Python API Reference

### UdnaSDK Class

The main entry point for all UDNA operations.

#### Constructor

```python
UdnaSDK(cache_enabled: bool = True, storage_dir: Optional[str] = None)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cache_enabled` | bool | True | Enable DID document caching |
| `storage_dir` | str | None | Directory for persistent identity storage |

#### Core Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `create_did(method="key", domain=None)` | Creates a new DID | `DidInfo` |
| `resolve_did(did)` | Resolves a DID to its document | `Dict` |
| `create_address(did, facet_id=0x02, flags=None)` | Creates a UDNA address | `UdnaAddressInfo` |
| `verify_address(address)` | Cryptographically verifies an address | `VerificationResult` |

#### Key Management Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `rotate_keys(did, reason="regular_rotation")` | Rotates keys with proof | `KeyRotationResult` |
| `export_identity(did, filepath, format="json")` | Exports identity to file | `bool` |
| `import_identity(filepath)` | Imports identity from file | `Optional[DidInfo]` |
| `load_identity(did, private_key_pem)` | Loads identity from PEM | `bool` |
| `list_identities()` | Lists all stored identities | `List[str]` |
| `get_did_info(did)` | Gets DID information | `Optional[Dict]` |

#### Privacy and Security Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `create_pairwise_did(my_did, peer_did)` | Creates relationship-specific DID | `DidInfo` |
| `initiate_secure_session(my_did, remote_did)` | Starts Noise protocol session | `SecureSession` |
| `encrypt_message(session_id, plaintext)` | Encrypts message with session key | `bytes` |
| `decrypt_message(session_id, ciphertext)` | Decrypts message with session key | `str` |

#### Example with All Features

```python
from udna_sdk import UdnaSDK

# Initialize with storage
sdk = UdnaSDK(storage_dir="./identities")

# Create identity
did = sdk.create_did()
print(f"DID: {did.did}")

# Export for backup
sdk.export_identity(did.did, "backup.json")

# Create address
address = sdk.create_address(did.did, flags=["messaging", "routing"])

# Rotate keys
result = sdk.rotate_keys(did.did, reason="regular_rotation")
print(f"Keys rotated: {result.success}")

# Create pairwise DID for privacy
peer_did = "did:key:z6MknVNjGKcWuUoxFXKmg29XV5RHkmx7gVvoYLGS8Qt4uACp"
pairwise = sdk.create_pairwise_did(did.did, peer_did)
print(f"Pairwise DID: {pairwise.did}")

# List all identities
identities = sdk.list_identities()
print(f"Stored identities: {identities}")
```

### Data Models

#### DidInfo

| Attribute | Type | Description |
|-----------|------|-------------|
| `did` | str | Full DID string |
| `method` | str | DID method (e.g., "key") |
| `identifier` | str | Method-specific identifier |
| `created_at` | str | ISO timestamp of creation |
| `private_key_pem` | str | PEM-encoded private key (optional) |

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

#### KeyRotationResult

| Attribute | Type | Description |
|-----------|------|-------------|
| `success` | bool | True if rotation succeeded |
| `did` | str | DID that was rotated |
| `old_key_fingerprint` | str | Fingerprint of old key |
| `new_key_fingerprint` | str | Fingerprint of new key |
| `rotated_at` | str | ISO timestamp of rotation |
| `error` | str or None | Error message if failed |

#### SecureSession

| Attribute | Type | Description |
|-----------|------|-------------|
| `session_id` | str | Unique session identifier |
| `local_did` | str | Local party DID |
| `remote_did` | str | Remote party DID |
| `established_at` | str | ISO timestamp of establishment |
| `session_key_hash` | str | Hash of session key |

### AddressFlags Enum

Flags control address behavior and capabilities.

| Flag | Value | Description |
|------|-------|-------------|
| `DEFAULT` | 0 | No special flags |
| `MESSAGING_ENABLED` | 1 | Enables messaging capabilities |
| `ROUTING_ENABLED` | 2 | Enables routing hints |
| `EPHEMERAL` | 4 | Address is temporary |
| `PRIORITY_HIGH` | 8 | High priority handling |
| `ENCRYPTED` | 16 | Encryption enabled |

**Usage:**
```python
from udna_sdk import AddressFlags

address = sdk.create_address(
    did.did,
    flags=["messaging", "routing", "priority"]
)
```

### Facet IDs

Facets represent different service types.

| Facet ID | Service Type | Description |
|----------|--------------|-------------|
| 0x01 | Control | Management and configuration |
| 0x02 | Messaging | Communication services |
| 0x03 | Telemetry | Monitoring and analytics |

---

## Command Line Interface

The SDK installs a global `udna` command.

### Commands

#### Create Identity

```bash
udna create [options]

Options:
  -m, --method {key,web}    DID method (default: key)
  -d, --domain DOMAIN       Domain for did:web method
  -f, --facet FACET         Facet ID (default: 0x02)
  --flags FLAGS...          Address flags
  -o, --output FILE         Save address to file
  -e, --export FILE         Export identity to file
  -s, --storage DIR         Storage directory for identities
  --format {text,json}      Output format (default: text)

Examples:
  udna create
  udna create --method web --domain example.com
  udna create --flags messaging routing priority
  udna create --storage ./ids --export alice.json
  udna create --format json
```

#### Rotate Keys

```bash
udna rotate DID [options]

Options:
  -r, --reason {regular_rotation,compromised,expired}
                        Rotation reason (default: regular_rotation)
  -i, --identity-file FILE
                        Identity JSON file to load
  -s, --storage DIR    Storage directory for identities

Examples:
  udna rotate "did:key:z6Mkk..."
  udna rotate "did:key:z6Mkk..." --reason compromised
  udna rotate "did:key:z6Mkk..." --identity-file alice.json
```

#### Export Identity

```bash
udna export DID --output FILE [options]

Options:
  -o, --output FILE    Output file path (required)
  --format {json,pem}  Export format (default: json)

Examples:
  udna export "did:key:z6Mkk..." --output backup.json
  udna export "did:key:z6Mkk..." --output key.pem --format pem
```

#### List Identities

```bash
udna list [options]

Options:
  -s, --storage DIR    Storage directory

Examples:
  udna list
  udna list --storage ./identities
```

#### Verify Address

```bash
udna verify [options]

Options:
  -a, --address ADDRESS    UDNA address to verify
  -f, --file FILE          JSON file containing address
  --format {text,json}     Output format (default: text)

Examples:
  udna verify --address "7XFJXFpgRQ..."
  udna verify --file identity.json
  udna verify --address "7XFJXFpgRQ..." --format json
```

#### Get Information

```bash
udna info [options]

Options:
  -d, --did DID            DID to inspect
  -a, --address ADDRESS    UDNA address to inspect

Examples:
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

## Advanced Features

### Key Rotation

Rotate keys securely with cryptographic proof of ownership.

```python
from udna_sdk import UdnaSDK

sdk = UdnaSDK()
did = sdk.create_did()

# Create address before rotation
addr1 = sdk.create_address(did.did, flags=["messaging"])

# Rotate keys
result = sdk.rotate_keys(did.did, reason="regular_rotation")
print(f"Rotation successful: {result.success}")
print(f"Old key: {result.old_key_fingerprint}")
print(f"New key: {result.new_key_fingerprint}")

# Create address after rotation (still valid)
addr2 = sdk.create_address(did.did, flags=["messaging"])

# Both addresses remain verifiable
assert sdk.verify_address(addr1.address).is_valid
assert sdk.verify_address(addr2.address).is_valid
```

### Identity Export and Import

Export identities for backup, migration, or secure storage.

```bash
# Export to JSON
udna export "did:key:z6Mkk..." --output backup.json

# Export to PEM (raw private key)
udna export "did:key:z6Mkk..." --output key.pem --format pem
```

```python
# Python API
sdk = UdnaSDK()

# Export
did = sdk.create_did()
sdk.export_identity(did.did, "backup.json")

# Import in new instance
sdk2 = UdnaSDK()
imported = sdk2.import_identity("backup.json")
print(f"Imported: {imported.did}")
```

### Pairwise DIDs

Create relationship-specific DIDs for privacy.

```python
sdk = UdnaSDK()
my_did = sdk.create_did()
peer_did = "did:key:z6MknVNjGKcWuUoxFXKmg29XV5RHkmx7gVvoYLGS8Qt4uACp"

# Create pairwise DID for this relationship only
pairwise = sdk.create_pairwise_did(my_did.did, peer_did)
print(f"Pairwise DID: {pairwise.did}")

# Use pairwise DID for all communications with this peer
address = sdk.create_address(pairwise.did, flags=["messaging"])
```

### Secure Messaging with Noise Protocol

Establish encrypted communication channels using the Noise protocol.

```python
# Alice and Bob create their identities
alice = UdnaSDK()
bob = UdnaSDK()
alice_did = alice.create_did()
bob_did = bob.create_did()

# Alice initiates secure session
session = alice.initiate_secure_session(alice_did.did, bob_did.did)
print(f"Session ID: {session.session_id}")

# Encrypt and send message
encrypted = alice.encrypt_message(session.session_id, "Hello Bob, this is secret!")

# Bob decrypts (session establishment would complete the handshake)
# decrypted = bob.decrypt_message(session.session_id, encrypted)
```

### Persistent Storage Directory

Configure a storage directory for automatic identity persistence.

```bash
# CLI usage
udna create --storage ./identities
udna list --storage ./identities
```

```python
# Python API
sdk = UdnaSDK(storage_dir="./identities")

# Identities are automatically saved
did = sdk.create_did()

# Later, list all stored identities
identities = sdk.list_identities()
print(f"Stored: {identities}")
```

---

## Examples

### Batch Identity Creation

```python
from udna_sdk import UdnaSDK
import json

sdk = UdnaSDK(storage_dir="./identities")
identities = []

for i in range(10):
    did = sdk.create_did()
    address = sdk.create_address(did.did, flags=["messaging"])
    identities.append({
        "index": i,
        "did": did.did,
        "address": address.address
    })

with open("batch_identities.json", "w") as f:
    json.dump(identities, f, indent=2)
```

### Verification with Error Handling

```python
from udna_sdk import UdnaSDK

sdk = UdnaSDK()
result = sdk.verify_address(address_string)

if result.is_valid:
    print(f"Address belongs to DID: {result.did}")
    print(f"Verified at: {result.verified_at}")
else:
    print(f"Verification failed: {result.error}")
```

### Custom Facet Configuration

```python
from udna_sdk import UdnaSDK

sdk = UdnaSDK()
did = sdk.create_did()

# Control facet (0x01) - Management
control = sdk.create_address(did.did, facet_id=0x01)
print(f"Control: {control.address[:30]}...")

# Messaging facet (0x02) - Communication
messaging = sdk.create_address(
    did.did,
    facet_id=0x02,
    flags=["messaging", "routing"]
)
print(f"Messaging: {messaging.address[:30]}...")

# Telemetry facet (0x03) - Analytics
telemetry = sdk.create_address(did.did, facet_id=0x03)
print(f"Telemetry: {telemetry.address[:30]}...")
```

### Complete Identity Lifecycle

```python
from udna_sdk import UdnaSDK

# 1. Initialize with storage
sdk = UdnaSDK(storage_dir="./identities")

# 2. Create identity
did = sdk.create_did()
print(f"Created: {did.did}")

# 3. Export backup
sdk.export_identity(did.did, "backup.json")

# 4. Create addresses
address1 = sdk.create_address(did.did, flags=["messaging"])
address2 = sdk.create_address(did.did, facet_id=0x03)

# 5. Rotate keys periodically
result = sdk.rotate_keys(did.did, reason="regular_rotation")
print(f"Keys rotated: {result.success}")

# 6. Verify all addresses remain valid
assert sdk.verify_address(address1.address).is_valid
assert sdk.verify_address(address2.address).is_valid

# 7. List stored identities
print(f"Stored: {sdk.list_identities()}")
```

---

## Architecture

The SDK implements the following specifications:

- **W3C DID Core 1.0** - Decentralized Identifier specification
- **did:key Method** - Cryptographic key-based DIDs
- **did:web Method** - Web-based DIDs
- **Ed25519** - Digital signatures for authentication
- **Base58** - Encoding for addresses and keys
- **Noise Protocol** - Secure channel establishment

### Address Structure

A UDNA address is a binary structure containing:

| Field | Size | Description |
|-------|------|-------------|
| Version | 1 byte | Protocol version (1) |
| DID Type | 1 byte | Method identifier (0x01 for did:key) |
| DID Length | 2 bytes | Length of DID string |
| DID | variable | Full DID string |
| Key Hint | 1 byte + variable | Truncated key fingerprint |
| Route Hint | 1 byte + variable | Routing information |
| Flags | 2 bytes | Behavioral flags bitmask |
| Nonce | 8 bytes | 64-bit random value |
| Signature | 2 bytes + variable | Ed25519 signature |

### DID Resolution Flow

1. Check local cache for DID document
2. If not cached, resolve using method-specific resolver
3. Cache document with TTL (default 3600 seconds)
4. Return DID document for verification

### Cryptographic Verification

1. Decode base58 address to bytes
2. Parse binary structure
3. Extract DID and signature
4. Resolve DID document to get public key
5. Recreate message without signature
6. Verify Ed25519 signature
7. Return verification result

### Key Rotation Flow

1. Generate new key pair
2. Create rotation proof signed by old key
3. Update DID document with new key
4. Store rotation proof for audit
5. Return new key fingerprint

---

## Security

### Key Management

Private keys are stored in memory only during SDK instance lifetime.

```python
# Keys are automatically managed
sdk = UdnaSDK()
did = sdk.create_did()  # Key stored internally
address = sdk.create_address(did.did)  # Key used for signing

# Key is lost when SDK instance is destroyed
del sdk
```

For persistent storage, use export functionality:

```python
# Export for secure storage
sdk.export_identity(did.did, "secure_backup.json", format="json")

# Store the file in a secure location, not in code
```

### Signature Verification

All UDNA addresses are cryptographically signed. The SDK automatically:

1. Extracts public key from DID document
2. Recreates the signed message
3. Verifies the Ed25519 signature
4. Returns verification result

### Best Practices

- Always verify addresses before trusting them
- Store private keys securely, never in code
- Use different facets for different services
- Rotate keys periodically
- Enable logging in production for audit trails
- Use pairwise DIDs for relationship-specific privacy
- Export and backup identities regularly

### Rotation Reasons

| Reason | Code | Use Case |
|--------|------|----------|
| `regular_rotation` | 1 | Scheduled key rotation |
| `compromised` | 2 | Key compromise suspected |
| `expired` | 3 | Key lifetime exceeded |

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

### Building Package

```bash
pip install build twine
python -m build
twine upload dist/*
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-04 | Initial release |
| 1.0.1 | 2026-04-04 | Fix imports, add AddressFlags |
| 1.0.2 | 2026-04-04 | Production ready release |
| 1.1.0 | 2026-04-04 | Key rotation, export/import, pairwise DIDs, secure messaging |
| 1.2.0 | 2026-07-03 | Security fix

---

## License

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
- **Issues**: [GitHub Issues](https://github.com/sirraya-labs/udna-sdk/issues)
- **Email**: [amir@sirraya.org](mailto:amir@sirraya.org)

---



## Citation

If you use this SDK in research or production, please cite:

```bibtex
@software{sirraya_udna_sdk_2026,
  title = {Sirraya Labs UDNA SDK},
  author = {Amir Hameed Mir, Sirraya Labs},
  year = {2026},
  version = {1.1.0},
  url = {https://github.com/sirraya-labs/udna-sdk},
  note = {W3C Universal DID-Native Addressing Implementation}
}
```



