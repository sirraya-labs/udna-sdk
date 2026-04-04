#!/usr/bin/env python3
"""
UDNA SDK - Universal DID-Native Addressing Software Development Kit
A comprehensive, production-ready SDK for integrating UDNA functionality.

Version: 1.0.0
License: MIT
Author: UDNA Development Team

Features:
- DID generation (did:key method)
- UDNA address creation and verification
- Cryptographic signature validation
- Command-line interface
- PyPI package ready
"""

import argparse
import base58
import secrets
import logging
import sys
import json
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

# Cryptography imports
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# UDNA imports
from udna import (
    Did,
    DidKeyMethod,
    UdnaAddress,
    DidResolver,
)


# ============================================================================
# Configuration and Constants
# ============================================================================

VERSION = "1.0.0"

class AddressFlags(Enum):
    """Standard UDNA address flags"""
    DEFAULT = 0
    MESSAGING_ENABLED = 1
    ROUTING_ENABLED = 2
    EPHEMERAL = 4
    PRIORITY_HIGH = 8
    ENCRYPTED = 16
    
    @classmethod
    def from_string(cls, flag_str: str) -> 'AddressFlags':
        """Convert string to flag enum"""
        mapping = {
            'default': cls.DEFAULT,
            'messaging': cls.MESSAGING_ENABLED,
            'routing': cls.ROUTING_ENABLED,
            'ephemeral': cls.EPHEMERAL,
            'priority': cls.PRIORITY_HIGH,
            'encrypted': cls.ENCRYPTED
        }
        return mapping.get(flag_str.lower(), cls.DEFAULT)


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class UdnaAddressInfo:
    """Human-readable UDNA address information"""
    address: str
    did: str
    facet_id: int
    flags: List[str]
    nonce: int
    created_at: str
    
    @classmethod
    def from_udna_address(cls, addr: UdnaAddress) -> 'UdnaAddressInfo':
        """Create from UdnaAddress object"""
        flag_names = []
        flags_value = addr.flags
        for flag in AddressFlags:
            if flags_value & flag.value:
                flag_names.append(flag.name.lower())
        
        return cls(
            address=base58.b58encode(addr.encode()).decode(),
            did=str(addr.did),
            facet_id=addr.facet_id,
            flags=flag_names,
            nonce=addr.nonce,
            created_at=datetime.now().isoformat()
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class DidInfo:
    """DID information"""
    did: str
    method: str
    identifier: str
    created_at: str
    
    @classmethod
    def from_did(cls, did: Did) -> 'DidInfo':
        """Create from Did object"""
        return cls(
            did=str(did),
            method=did.method,
            identifier=did.identifier,
            created_at=datetime.now().isoformat()
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class VerificationResult:
    """Address verification result"""
    is_valid: bool
    address: str
    did: str
    verified_at: str
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=indent)


# ============================================================================
# SDK Core Class
# ============================================================================

class UdnaSDK:
    """
    Universal DID-Native Addressing SDK
    
    This SDK provides a clean interface for working with UDNA addresses
    and DIDs. It supports DID generation, address creation, and
    cryptographic verification.
    
    Example:
        sdk = UdnaSDK()
        
        # Create a DID
        did_info = sdk.create_did()
        
        # Create an address
        address_info = sdk.create_address(did_info.did)
        
        # Verify the address
        result = sdk.verify_address(address_info.address)
    """
    
    def __init__(self, cache_enabled: bool = True):
        """
        Initialize the UDNA SDK.
        
        Args:
            cache_enabled: Enable DID document caching
        """
        self.resolver = DidResolver() if cache_enabled else None
        self._active_keys: Dict[str, ed25519.Ed25519PrivateKey] = {}
        self._logger = logging.getLogger(__name__)
        
    def create_did(self) -> DidInfo:
        """
        Create a new DID using the 'key' method.
        
        Returns:
            DidInfo object containing the created DID
            
        Raises:
            Exception: If DID creation fails
        """
        self._logger.info("Creating new DID")
        
        # Generate key pair and DID
        did, private_key = DidKeyMethod.generate()
        
        # Store private key for address creation
        did_str = str(did)
        self._active_keys[did_str] = private_key
        
        # Create DID info
        did_info = DidInfo.from_did(did)
        
        self._logger.info(f"DID created successfully: {did_str[:40]}...")
        return did_info
    
    def create_address(self, 
                       did: str,
                       facet_id: int = 0x02,
                       flags: List[str] = None) -> UdnaAddressInfo:
        """
        Create a UDNA address for the given DID.
        
        Args:
            did: DID string (e.g., "did:key:z6Mkk...")
            facet_id: Facet identifier (0x01=Control, 0x02=Messaging, 0x03=Telemetry)
            flags: List of flag strings (e.g., ["messaging", "routing"])
            
        Returns:
            UdnaAddressInfo containing the generated address
            
        Raises:
            ValueError: If DID not found or invalid
        """
        self._logger.info(f"Creating UDNA address for DID: {did[:40]}...")
        
        # Check if we have the private key
        if did not in self._active_keys:
            raise ValueError(f"No private key found for DID: {did}")
        
        private_key = self._active_keys[did]
        
        # Parse DID
        did_obj = Did.parse(did)
        
        # Convert flags to bitmask
        flags_value = 0
        if flags:
            for flag_str in flags:
                flag = AddressFlags.from_string(flag_str)
                flags_value |= flag.value
        
        # Create address
        address = UdnaAddress(
            did=did_obj,
            facet_id=facet_id,
            nonce=secrets.randbits(64),
            flags=flags_value
        )
        
        # Sign the address
        address_bytes = address.encode()
        signature = private_key.sign(address_bytes)
        address.signature = signature
        
        # Convert to user-friendly format
        address_info = UdnaAddressInfo.from_udna_address(address)
        
        self._logger.info(f"Address created successfully: {address_info.address[:40]}...")
        return address_info
    
    def verify_address(self, address: str) -> VerificationResult:
        """
        Verify a UDNA address cryptographically.
        
        Args:
            address: Base58-encoded UDNA address
            
        Returns:
            VerificationResult with status and details
        """
        self._logger.info("Verifying UDNA address")
        
        try:
            # Decode address
            address_bytes = base58.b58decode(address)
            addr_obj = UdnaAddress.decode(address_bytes)
            
            # Resolve DID to get public key
            did_doc = DidKeyMethod.resolve(addr_obj.did)
            
            # Extract public key from DID document
            public_key_multibase = did_doc.verification_method[0].public_key_multibase
            multicodec_key = base58.b58decode(public_key_multibase[1:])
            
            # Remove multicodec prefix (0xed01) to get raw public key
            if len(multicodec_key) >= 2 and multicodec_key[:2] == b'\xed\x01':
                raw_public_key = multicodec_key[2:]
            else:
                raw_public_key = multicodec_key
            
            # Recreate public key
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_public_key)
            
            # Recreate message without signature
            addr_without_sig = UdnaAddress(
                version=addr_obj.version,
                did_type=addr_obj.did_type,
                did=addr_obj.did,
                facet_id=addr_obj.facet_id,
                key_hint=addr_obj.key_hint,
                route_hint=addr_obj.route_hint,
                flags=addr_obj.flags,
                nonce=addr_obj.nonce,
                signature=b''
            )
            message = addr_without_sig.encode()
            
            # Verify signature
            public_key.verify(addr_obj.signature, message)
            
            self._logger.info("Address verification successful")
            return VerificationResult(
                is_valid=True,
                address=address,
                did=str(addr_obj.did),
                verified_at=datetime.now().isoformat()
            )
            
        except Exception as e:
            self._logger.error(f"Address verification failed: {e}")
            return VerificationResult(
                is_valid=False,
                address=address,
                did="unknown",
                verified_at=datetime.now().isoformat(),
                error=str(e)
            )
    
    def get_did_info(self, did: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a DID.
        
        Args:
            did: DID string to look up
            
        Returns:
            Dictionary with DID information or None if not found
        """
        if did in self._active_keys:
            return {
                "did": did,
                "has_private_key": True,
                "method": Did.parse(did).method
            }
        return None


# ============================================================================
# CLI Implementation
# ============================================================================

def setup_logging(verbose: bool = False):
    """Configure logging for CLI"""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(levelname)s: %(message)s'
    )


def cmd_create(args) -> int:
    """Handle 'create' command - Create a new DID and address"""
    sdk = UdnaSDK()
    
    # Create DID
    print("Creating DID...", file=sys.stderr)
    did_info = sdk.create_did()
    
    # Parse flags
    flags = args.flags if args.flags else []
    
    # Create address
    print("Creating UDNA address...", file=sys.stderr)
    address_info = sdk.create_address(
        did=did_info.did,
        facet_id=args.facet,
        flags=flags
    )
    
    # Output based on format
    if args.format == 'json':
        result = {
            "did": did_info.to_dict(),
            "address": address_info.to_dict()
        }
        print(json.dumps(result, indent=2))
    else:
        print("\n" + "=" * 70)
        print("UDNA ADDRESS GENERATED SUCCESSFULLY")
        print("=" * 70)
        print(f"\nDID:")
        print(f"  {did_info.did}")
        print(f"\nUDNA Address:")
        print(f"  {address_info.address}")
        print(f"\nAddress Details:")
        print(f"  Facet ID: 0x{address_info.facet_id:02x}")
        print(f"  Flags: {', '.join(address_info.flags) if address_info.flags else 'none'}")
        print(f"  Nonce: {address_info.nonce}")
        print(f"\nCreated: {address_info.created_at}")
        print("=" * 70)
    
    # Save to file if requested
    if args.output:
        output_data = {
            "did": did_info.to_dict(),
            "address": address_info.to_dict()
        }
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\nSaved to: {args.output}", file=sys.stderr)
    
    return 0


def cmd_verify(args) -> int:
    """Handle 'verify' command - Verify a UDNA address"""
    sdk = UdnaSDK()
    
    # Read address from file or argument
    if args.file:
        with open(args.file, 'r') as f:
            data = json.load(f)
            address = data.get('address', {}).get('address')
            if not address:
                address = data.get('address')
    else:
        address = args.address
    
    if not address:
        print("Error: No address provided", file=sys.stderr)
        return 1
    
    # Verify address
    result = sdk.verify_address(address)
    
    # Output based on format
    if args.format == 'json':
        print(result.to_json())
    else:
        print("\n" + "=" * 70)
        if result.is_valid:
            print("VERIFICATION RESULT: VALID")
        else:
            print("VERIFICATION RESULT: INVALID")
        print("=" * 70)
        print(f"\nAddress: {result.address[:50]}...")
        print(f"DID: {result.did}")
        print(f"Verified: {result.verified_at}")
        if result.error:
            print(f"Error: {result.error}")
        print("=" * 70)
    
    return 0 if result.is_valid else 1


def cmd_info(args) -> int:
    """Handle 'info' command - Get information about a DID or address"""
    sdk = UdnaSDK()
    
    if args.did:
        # Parse DID
        did_obj = Did.parse(args.did)
        print("\n" + "=" * 70)
        print("DID INFORMATION")
        print("=" * 70)
        print(f"\nDID: {args.did}")
        print(f"Method: {did_obj.method}")
        print(f"Identifier: {did_obj.identifier}")
        
        # Try to resolve
        try:
            doc = DidKeyMethod.resolve(did_obj)
            print(f"\nVerification Methods: {len(doc.verification_method)}")
            print(f"Created: {doc.created}")
            print(f"Updated: {doc.updated}")
        except:
            print("\nNote: Could not resolve DID document")
        print("=" * 70)
        
    elif args.address:
        # Parse address
        try:
            address_bytes = base58.b58decode(args.address)
            addr_obj = UdnaAddress.decode(address_bytes)
            print("\n" + "=" * 70)
            print("UDNA ADDRESS INFORMATION")
            print("=" * 70)
            print(f"\nAddress: {args.address[:50]}...")
            print(f"DID: {addr_obj.did}")
            print(f"Facet ID: 0x{addr_obj.facet_id:02x}")
            print(f"Flags: {addr_obj.flags}")
            print(f"Nonce: {addr_obj.nonce}")
            print(f"Signature Length: {len(addr_obj.signature)} bytes")
            print("=" * 70)
        except Exception as e:
            print(f"Error decoding address: {e}", file=sys.stderr)
            return 1
    
    return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='UDNA SDK - Universal DID-Native Addressing Toolkit',
        epilog='Example: udna create --flags messaging routing'
    )
    parser.add_argument('--version', action='version', version=f'UDNA SDK v{VERSION}')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new DID and UDNA address')
    create_parser.add_argument('-f', '--facet', type=int, default=0x02,
                               help='Facet ID (default: 0x02 for messaging)')
    create_parser.add_argument('--flags', nargs='*', 
                               choices=['default', 'messaging', 'routing', 'ephemeral', 'priority', 'encrypted'],
                               help='Address flags')
    create_parser.add_argument('-o', '--output', help='Save output to file (JSON format)')
    create_parser.add_argument('--format', choices=['text', 'json'], default='text',
                               help='Output format')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify a UDNA address')
    verify_group = verify_parser.add_mutually_exclusive_group(required=True)
    verify_group.add_argument('-a', '--address', help='UDNA address to verify')
    verify_group.add_argument('-f', '--file', help='JSON file containing address')
    verify_parser.add_argument('--format', choices=['text', 'json'], default='text',
                               help='Output format')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Get information about a DID or address')
    info_group = info_parser.add_mutually_exclusive_group(required=True)
    info_group.add_argument('-d', '--did', help='DID to inspect')
    info_group.add_argument('-a', '--address', help='UDNA address to inspect')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Execute command
    if args.command == 'create':
        return cmd_create(args)
    elif args.command == 'verify':
        return cmd_verify(args)
    elif args.command == 'info':
        return cmd_info(args)
    else:
        parser.print_help()
        return 1


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'UdnaSDK',
    'UdnaAddressInfo',
    'DidInfo',
    'VerificationResult',
    'AddressFlags',
    'VERSION'
]

# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    sys.exit(main())