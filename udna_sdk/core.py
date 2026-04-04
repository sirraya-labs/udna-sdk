#!/usr/bin/env python3
"""
UDNA SDK - Universal DID-Native Addressing Software Development Kit
A comprehensive, production-ready SDK for integrating UDNA functionality.

Version: 1.1.0
License: MIT
Author: Sirraya Labs

Features:
- DID generation (did:key, did:web methods)
- UDNA address creation and verification
- Cryptographic signature validation
- Key rotation and management
- Pairwise DIDs for privacy
- Secure messaging with Noise protocol
- File export/import for keys and identities
- Command-line interface
"""

import argparse
import hashlib
import base58
import secrets
import logging
import sys
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# UDNA imports
from .udna import (
    Did,
    DidKeyMethod,
    DidWebMethod,
    UdnaAddress,
    DidResolver,
    KeyRotationManager,
    PairwiseDidManager,
    NoiseHandshake,
    SecureMessaging,
    AddressFlags as UdnaAddressFlags
)


# ============================================================================
# Configuration and Constants
# ============================================================================

VERSION = "1.1.0"

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
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class DidInfo:
    """DID information"""
    did: str
    method: str
    identifier: str
    created_at: str
    private_key_pem: Optional[str] = None
    
    @classmethod
    def from_did(cls, did: Did, private_key: ed25519.Ed25519PrivateKey = None) -> 'DidInfo':
        info = cls(
            did=str(did),
            method=did.method,
            identifier=did.identifier,
            created_at=datetime.now().isoformat()
        )
        if private_key:
            info.private_key_pem = cls._export_private_key(private_key)
        return info
    
    @staticmethod
    def _export_private_key(private_key: ed25519.Ed25519PrivateKey) -> str:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if data.get('private_key_pem'):
            data['private_key_pem'] = '[REDACTED]'  # Don't expose in JSON
        return data
    
    def to_json(self, indent: int = 2) -> str:
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
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class KeyRotationResult:
    """Key rotation result"""
    success: bool
    did: str
    old_key_fingerprint: str
    new_key_fingerprint: str
    rotated_at: str
    proof: Optional[bytes] = None
    error: Optional[str] = None


@dataclass
class SecureSession:
    """Secure communication session"""
    session_id: str
    local_did: str
    remote_did: str
    established_at: str
    session_key_hash: str


# ============================================================================
# Enhanced SDK Core Class
# ============================================================================

class UdnaSDK:
    """
    Universal DID-Native Addressing SDK with full feature set.
    
    Features:
    - DID creation (did:key, did:web)
    - UDNA address creation and verification
    - Key rotation and management
    - Pairwise DIDs for privacy
    - Secure messaging with Noise protocol
    - Export/import identities to/from files
    """
    
    def __init__(self, cache_enabled: bool = True, storage_dir: Optional[str] = None):
        """
        Initialize the UDNA SDK.
        
        Args:
            cache_enabled: Enable DID document caching
            storage_dir: Directory for storing keys and identities (optional)
        """
        self.resolver = DidResolver() if cache_enabled else None
        self.rotation_manager = KeyRotationManager()
        self.pairwise_manager = PairwiseDidManager()
        self.handshake_handler = NoiseHandshake()
        self.messaging = SecureMessaging()
        self._active_keys: Dict[str, ed25519.Ed25519PrivateKey] = {}
        self._active_sessions: Dict[str, Dict] = {}
        self._logger = logging.getLogger(__name__)
        
        # Setup storage
        self.storage_dir = storage_dir
        if storage_dir:
            Path(storage_dir).mkdir(parents=True, exist_ok=True)
    
    # ========================================================================
    # DID Operations
    # ========================================================================
    
    def create_did(self, method: str = "key", domain: str = None) -> DidInfo:
        """
        Create a new DID.
        
        Args:
            method: DID method ("key" or "web")
            domain: Domain name for did:web (required if method="web")
            
        Returns:
            DidInfo object containing the created DID
        """
        self._logger.info(f"Creating new DID with method: {method}")
        
        if method == "key":
            did, private_key = DidKeyMethod.generate()
        elif method == "web":
            if not domain:
                raise ValueError("Domain required for did:web method")
            did = DidWebMethod.create(domain)
            private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"Unsupported DID method: {method}")
        
        did_str = str(did)
        self._active_keys[did_str] = private_key
        did_info = DidInfo.from_did(did, private_key)
        
        # Save to storage if configured
        if self.storage_dir:
            self._save_identity(did_info, private_key)
        
        self._logger.info(f"DID created: {did_str[:40]}...")
        return did_info
    
    def resolve_did(self, did: str) -> Dict[str, Any]:
        """
        Resolve a DID to get its document.
        
        Args:
            did: DID string to resolve
            
        Returns:
            Dictionary with DID document information
        """
        self._logger.info(f"Resolving DID: {did[:40]}...")
        did_obj = Did.parse(did)
        
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        document = loop.run_until_complete(self.resolver.resolve(did_obj))
        loop.close()
        
        return {
            "did": str(did_obj),
            "verification_methods": [
                {
                    "id": vm.id,
                    "type": vm.type,
                    "controller": vm.controller
                } for vm in document.verification_method
            ],
            "created": document.created,
            "updated": document.updated
        }
    
    # ========================================================================
    # Address Operations
    # ========================================================================
    
    def create_address(self, 
                       did: str,
                       facet_id: int = 0x02,
                       flags: List[str] = None) -> UdnaAddressInfo:
        """
        Create a UDNA address for the given DID.
        """
        self._logger.info(f"Creating UDNA address for DID: {did[:40]}...")
        
        if did not in self._active_keys:
            raise ValueError(f"No private key found for DID: {did}. Use load_identity() first.")
        
        private_key = self._active_keys[did]
        did_obj = Did.parse(did)
        
        flags_value = 0
        if flags:
            for flag_str in flags:
                flag = AddressFlags.from_string(flag_str)
                flags_value |= flag.value
        
        address = UdnaAddress(
            did=did_obj,
            facet_id=facet_id,
            nonce=secrets.randbits(64),
            flags=flags_value
        )
        
        address_bytes = address.encode()
        signature = private_key.sign(address_bytes)
        address.signature = signature
        
        address_info = UdnaAddressInfo.from_udna_address(address)
        self._logger.info(f"Address created: {address_info.address[:40]}...")
        return address_info
    
    def verify_address(self, address: str) -> VerificationResult:
        """
        Verify a UDNA address cryptographically.
        """
        self._logger.info("Verifying UDNA address")
        
        try:
            address_bytes = base58.b58decode(address)
            addr_obj = UdnaAddress.decode(address_bytes)
            
            did_doc = DidKeyMethod.resolve(addr_obj.did)
            public_key_multibase = did_doc.verification_method[0].public_key_multibase
            multicodec_key = base58.b58decode(public_key_multibase[1:])
            
            if len(multicodec_key) >= 2 and multicodec_key[:2] == b'\xed\x01':
                raw_public_key = multicodec_key[2:]
            else:
                raw_public_key = multicodec_key
            
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_public_key)
            
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
            public_key.verify(addr_obj.signature, message)
            
            return VerificationResult(
                is_valid=True,
                address=address,
                did=str(addr_obj.did),
                verified_at=datetime.now().isoformat()
            )
        except Exception as e:
            return VerificationResult(
                is_valid=False,
                address=address,
                did="unknown",
                verified_at=datetime.now().isoformat(),
                error=str(e)
            )
    
    # ========================================================================
    # Key Management
    # ========================================================================
    
    def rotate_keys(self, did: str, reason: str = "regular_rotation") -> KeyRotationResult:
        """
        Rotate keys for a DID.
        
        Args:
            did: DID to rotate keys for
            reason: Rotation reason ("regular_rotation", "compromised", "expired")
            
        Returns:
            KeyRotationResult with rotation details
        """
        self._logger.info(f"Rotating keys for DID: {did[:40]}...")
        
        try:
            if did not in self._active_keys:
                raise ValueError(f"No active key for DID: {did}")
            
            old_key = self._active_keys[did]
            new_key = ed25519.Ed25519PrivateKey.generate()
            
            reason_map = {"regular_rotation": 1, "compromised": 2, "expired": 3}
            reason_code = reason_map.get(reason, 1)
            
            did_obj = Did.parse(did)
            proof = self.rotation_manager.rotate_key(did_obj, old_key, new_key, reason_code)
            
            self._active_keys[did] = new_key
            
            # Save updated identity
            if self.storage_dir:
                did_info = DidInfo.from_did(did_obj, new_key)
                self._save_identity(did_info, new_key)
            
            return KeyRotationResult(
                success=True,
                did=did,
                old_key_fingerprint=hashlib.sha256(old_key.public_key().public_bytes_raw()).hexdigest()[:16],
                new_key_fingerprint=hashlib.sha256(new_key.public_key().public_bytes_raw()).hexdigest()[:16],
                rotated_at=datetime.now().isoformat(),
                proof=proof.sig_by_prev
            )
        except Exception as e:
            return KeyRotationResult(
                success=False,
                did=did,
                old_key_fingerprint="",
                new_key_fingerprint="",
                rotated_at=datetime.now().isoformat(),
                error=str(e)
            )
    
    def export_identity(self, did: str, filepath: str, format: str = "json") -> bool:
        """
        Export identity (DID and private key) to a file.
        
        Args:
            did: DID to export
            filepath: Path to save the identity
            format: Export format ("json" or "pem")
            
        Returns:
            True if successful, False otherwise
        """
        if did not in self._active_keys:
            self._logger.error(f"DID not found: {did}")
            return False
        
        private_key = self._active_keys[did]
        did_obj = Did.parse(did)
        
        if format == "json":
            identity = {
                "did": did,
                "method": did_obj.method,
                "identifier": did_obj.identifier,
                "private_key_pem": private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8'),
                "exported_at": datetime.now().isoformat(),
                "version": VERSION
            }
            with open(filepath, 'w') as f:
                json.dump(identity, f, indent=2)
        elif format == "pem":
            pem_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(filepath, 'wb') as f:
                f.write(pem_data)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        self._logger.info(f"Identity exported to: {filepath}")
        return True
    
    def import_identity(self, filepath: str) -> Optional[DidInfo]:
        """
        Import identity from a file.
        
        Args:
            filepath: Path to the identity file
            
        Returns:
            DidInfo if successful, None otherwise
        """
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        did = Did.parse(data['did'])
        pem_data = data['private_key_pem'].encode('utf-8')
        private_key = serialization.load_pem_private_key(pem_data, password=None)
        
        self._active_keys[str(did)] = private_key
        did_info = DidInfo.from_did(did, private_key)
        
        self._logger.info(f"Identity imported: {did_info.did[:40]}...")
        return did_info
    
    def load_identity(self, did: str, private_key_pem: str) -> bool:
        """
        Load an identity from PEM string.
        
        Args:
            did: DID string
            private_key_pem: PEM-encoded private key
            
        Returns:
            True if successful
        """
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'), 
                password=None
            )
            self._active_keys[did] = private_key
            self._logger.info(f"Identity loaded: {did[:40]}...")
            return True
        except Exception as e:
            self._logger.error(f"Failed to load identity: {e}")
            return False
    
    # ========================================================================
    # Pairwise DIDs
    # ========================================================================
    
    def create_pairwise_did(self, my_did: str, peer_did: str) -> DidInfo:
        """
        Create a pairwise DID for a specific relationship.
        
        Args:
            my_did: Your DID
            peer_did: Peer's DID
            
        Returns:
            DidInfo for the pairwise DID
        """
        self._logger.info(f"Creating pairwise DID for relationship")
        
        my_did_obj = Did.parse(my_did)
        peer_did_obj = Did.parse(peer_did)
        
        pairwise_did, private_key = self.pairwise_manager.generate_pairwise_did(
            my_did_obj, peer_did_obj
        )
        
        did_str = str(pairwise_did)
        self._active_keys[did_str] = private_key
        
        return DidInfo.from_did(pairwise_did, private_key)
    
    # ========================================================================
    # Secure Messaging
    # ========================================================================
    
    def initiate_secure_session(self, my_did: str, remote_did: str) -> SecureSession:
        """
        Initiate a secure Noise protocol session.
        
        Args:
            my_did: Your DID
            remote_did: Remote party's DID
            
        Returns:
            SecureSession information
        """
        if my_did not in self._active_keys:
            raise ValueError(f"No private key for DID: {my_did}")
        
        private_key = self._active_keys[my_did]
        my_did_obj = Did.parse(my_did)
        remote_did_obj = Did.parse(remote_did)
        
        session_id, message = self.handshake_handler.initiate_handshake(
            my_did_obj, private_key, remote_did_obj
        )
        
        self._active_sessions[session_id] = {
            'remote_did': remote_did,
            'state': 'initiated',
            'message': message
        }
        
        return SecureSession(
            session_id=session_id,
            local_did=my_did,
            remote_did=remote_did,
            established_at=datetime.now().isoformat(),
            session_key_hash="pending"
        )
    
    def respond_to_session(self, session_id: str, init_message: bytes) -> SecureSession:
        """
        Respond to a session initiation.
        
        Args:
            session_id: Session ID
            init_message: Initiation message from peer
            
        Returns:
            SecureSession information
        """
        # Implementation would complete handshake
        pass
    
    def encrypt_message(self, session_id: str, plaintext: str) -> bytes:
        """
        Encrypt a message using the session key.
        
        Args:
            session_id: Active session ID
            plaintext: Message to encrypt
            
        Returns:
            Encrypted message bytes
        """
        session = self._active_sessions.get(session_id)
        if not session or 'session_key' not in session:
            raise ValueError("No active session found")
        
        return self.messaging.encrypt_message(
            session['session_key'], 
            plaintext.encode('utf-8')
        )
    
    def decrypt_message(self, session_id: str, ciphertext: bytes) -> str:
        """
        Decrypt a message using the session key.
        
        Args:
            session_id: Active session ID
            ciphertext: Encrypted message bytes
            
        Returns:
            Decrypted message string
        """
        session = self._active_sessions.get(session_id)
        if not session or 'session_key' not in session:
            raise ValueError("No active session found")
        
        decrypted = self.messaging.decrypt_message(session['session_key'], ciphertext)
        return decrypted.decode('utf-8')
    
    # ========================================================================
    # Storage Operations
    # ========================================================================
    
    def _save_identity(self, did_info: DidInfo, private_key: ed25519.Ed25519PrivateKey):
        """Save identity to storage directory."""
        if not self.storage_dir:
            return
        
        filepath = Path(self.storage_dir) / f"{did_info.did.replace(':', '_')}.json"
        identity = {
            "did": did_info.did,
            "method": did_info.method,
            "identifier": did_info.identifier,
            "private_key_pem": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'),
            "created_at": did_info.created_at
        }
        with open(filepath, 'w') as f:
            json.dump(identity, f, indent=2)
    
    def list_identities(self) -> List[str]:
        """List all DIDs in storage."""
        if not self.storage_dir:
            return []
        
        identities = []
        for file in Path(self.storage_dir).glob("*.json"):
            with open(file, 'r') as f:
                data = json.load(f)
                identities.append(data.get('did', file.stem))
        return identities
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def get_did_info(self, did: str) -> Optional[Dict[str, Any]]:
        """Get information about a DID managed by this SDK instance."""
        if did in self._active_keys:
            return {
                "did": did,
                "has_private_key": True,
                "method": Did.parse(did).method
            }
        return None
    
    def list_active_dids(self) -> List[str]:
        """List all DIDs with active keys in memory."""
        return list(self._active_keys.keys())


# ============================================================================
# CLI Implementation (Enhanced)
# ============================================================================

def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')


def cmd_create(args) -> int:
    sdk = UdnaSDK(storage_dir=args.storage)
    
    print("Creating DID...", file=sys.stderr)
    did_info = sdk.create_did(method=args.method, domain=args.domain)
    
    flags = args.flags if args.flags else []
    print("Creating UDNA address...", file=sys.stderr)
    address_info = sdk.create_address(
        did=did_info.did,
        facet_id=args.facet,
        flags=flags
    )
    
    if args.export:
        sdk.export_identity(did_info.did, args.export)
        print(f"Identity exported to: {args.export}", file=sys.stderr)
    
    if args.format == 'json':
        result = {"did": did_info.to_dict(), "address": address_info.to_dict()}
        print(json.dumps(result, indent=2))
    else:
        print("\n" + "=" * 70)
        print("UDNA IDENTITY CREATED SUCCESSFULLY")
        print("=" * 70)
        print(f"\nDID:\n  {did_info.did}")
        print(f"\nUDNA Address:\n  {address_info.address}")
        print(f"\nAddress Details:")
        print(f"  Facet ID: 0x{address_info.facet_id:02x}")
        print(f"  Flags: {', '.join(address_info.flags) if address_info.flags else 'none'}")
        print(f"  Nonce: {address_info.nonce}")
        print(f"\nCreated: {address_info.created_at}")
        print("=" * 70)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({"did": did_info.did, "address": address_info.address}, f)
        print(f"\nSaved to: {args.output}", file=sys.stderr)
    
    return 0


def cmd_rotate(args) -> int:
    sdk = UdnaSDK(storage_dir=args.storage)
    
    # Load identity if needed
    if args.identity_file:
        sdk.import_identity(args.identity_file)
    
    result = sdk.rotate_keys(args.did, reason=args.reason)
    
    if result.success:
        print("\n" + "=" * 70)
        print("KEY ROTATION SUCCESSFUL")
        print("=" * 70)
        print(f"\nDID: {result.did}")
        print(f"Old Key Fingerprint: {result.old_key_fingerprint}")
        print(f"New Key Fingerprint: {result.new_key_fingerprint}")
        print(f"Rotated At: {result.rotated_at}")
        print("=" * 70)
        return 0
    else:
        print(f"\nRotation failed: {result.error}", file=sys.stderr)
        return 1


def cmd_export(args) -> int:
    sdk = UdnaSDK()
    
    # Need to have the key loaded
    print("Note: This requires the DID to be created in this session", file=sys.stderr)
    print("Use --did and ensure the identity is in memory", file=sys.stderr)
    
    if sdk.export_identity(args.did, args.output, format=args.format):
        print(f"Identity exported to: {args.output}")
        return 0
    else:
        print(f"Failed to export identity for DID: {args.did}", file=sys.stderr)
        return 1


def cmd_list(args) -> int:
    sdk = UdnaSDK(storage_dir=args.storage)
    identities = sdk.list_identities()
    
    print("\n" + "=" * 70)
    print("STORED IDENTITIES")
    print("=" * 70)
    for i, did in enumerate(identities, 1):
        print(f"  {i}. {did}")
    print("=" * 70)
    return 0


def cmd_verify(args) -> int:
    sdk = UdnaSDK()
    
    if args.file:
        with open(args.file, 'r') as f:
            data = json.load(f)
            address = data.get('address', {}).get('address') or data.get('address')
    else:
        address = args.address
    
    if not address:
        print("Error: No address provided", file=sys.stderr)
        return 1
    
    result = sdk.verify_address(address)
    
    if args.format == 'json':
        print(result.to_json())
    else:
        print("\n" + "=" * 70)
        print(f"VERIFICATION RESULT: {'VALID' if result.is_valid else 'INVALID'}")
        print("=" * 70)
        print(f"\nAddress: {result.address[:50]}...")
        print(f"DID: {result.did}")
        print(f"Verified: {result.verified_at}")
        if result.error:
            print(f"Error: {result.error}")
        print("=" * 70)
    
    return 0 if result.is_valid else 1


def main():
    parser = argparse.ArgumentParser(
        description='UDNA SDK - Universal DID-Native Addressing Toolkit',
        epilog='Example: udna create --flags messaging routing'
    )
    parser.add_argument('--version', action='version', version=f'UDNA SDK v{VERSION}')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new DID and UDNA address')
    create_parser.add_argument('-m', '--method', choices=['key', 'web'], default='key',
                               help='DID method (default: key)')
    create_parser.add_argument('-d', '--domain', help='Domain for did:web method')
    create_parser.add_argument('-f', '--facet', type=int, default=0x02,
                               help='Facet ID (default: 0x02 for messaging)')
    create_parser.add_argument('--flags', nargs='*', 
                               choices=['default', 'messaging', 'routing', 'ephemeral', 'priority', 'encrypted'],
                               help='Address flags')
    create_parser.add_argument('-o', '--output', help='Save address to file')
    create_parser.add_argument('-e', '--export', help='Export identity to file')
    create_parser.add_argument('-s', '--storage', help='Storage directory for identities')
    create_parser.add_argument('--format', choices=['text', 'json'], default='text',
                               help='Output format')
    
    # Rotate command
    rotate_parser = subparsers.add_parser('rotate', help='Rotate keys for a DID')
    rotate_parser.add_argument('did', help='DID to rotate keys for')
    rotate_parser.add_argument('-r', '--reason', choices=['regular_rotation', 'compromised', 'expired'],
                               default='regular_rotation', help='Rotation reason')
    rotate_parser.add_argument('-i', '--identity-file', help='Identity JSON file to load')
    rotate_parser.add_argument('-s', '--storage', help='Storage directory for identities')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export identity to file')
    export_parser.add_argument('did', help='DID to export')
    export_parser.add_argument('-o', '--output', required=True, help='Output file path')
    export_parser.add_argument('--format', choices=['json', 'pem'], default='json',
                               help='Export format')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List stored identities')
    list_parser.add_argument('-s', '--storage', help='Storage directory')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify a UDNA address')
    verify_group = verify_parser.add_mutually_exclusive_group(required=True)
    verify_group.add_argument('-a', '--address', help='UDNA address to verify')
    verify_group.add_argument('-f', '--file', help='JSON file containing address')
    verify_parser.add_argument('--format', choices=['text', 'json'], default='text',
                               help='Output format')
    
    args = parser.parse_args()
    setup_logging(args.verbose)
    
    if args.command == 'create':
        return cmd_create(args)
    elif args.command == 'rotate':
        return cmd_rotate(args)
    elif args.command == 'export':
        return cmd_export(args)
    elif args.command == 'list':
        return cmd_list(args)
    elif args.command == 'verify':
        return cmd_verify(args)
    else:
        parser.print_help()
        return 1


__all__ = [
    'UdnaSDK',
    'UdnaAddressInfo',
    'DidInfo',
    'VerificationResult',
    'KeyRotationResult',
    'SecureSession',
    'AddressFlags',
    'VERSION'
]

if __name__ == "__main__":
    sys.exit(main())