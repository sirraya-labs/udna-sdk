#!/usr/bin/env python3
"""
Hardened Noise Protocol Framework implementation — Noise_IK_25519_ChaChaPoly_SHA256

Implements the Noise IK pattern per the Noise Protocol Framework specification
(revision 34): https://noiseprotocol.org/noise.html

    <- s
    ...
    -> e, es, s, ss
    <- e, ee, se

This revision fixes the following issues found in the original draft:

  1. Missing `serialization` import (the original file could not run).
  2. Nonce-exhaustion handling: per spec, the nonce value 2**64-1 is RESERVED
     for REKEY() and must never be used to encrypt/decrypt a normal message.
     The original code only rejected n > MAX_NONCE, not n == MAX_NONCE.
  3. No validation that DH() outputs are non-zero. A malicious peer can send
     a low-order / invalid public key to force a known, attacker-predictable
     shared secret (a "small-subgroup" / contributory-behavior attack). Per
     spec section 9 ("Rogue key attacks"), implementations SHOULD reject
     these. This is now enforced on every mix_key() call.
  4. No maximum message-size enforcement. The spec bounds every Noise
     message (handshake or transport) to 65535 bytes.
  5. Blanket `ValueError` for everything, including authentication failures.
     Callers need to be able to distinguish "peer sent garbage / MITM" from
     "programmer misuse" without parsing strings. Introduces a small
     exception hierarchy instead.
  6. `NoiseSessionManager` had no locking despite being designed for
     concurrent use (e.g. many inbound handshakes at once).
  7. Best-effort zeroing of ephemeral/session key material after use where
     Python allows it (mutable bytearrays), and a documented caveat that
     CPython cannot guarantee secure erasure (no memory locking, potential
     copies via GC/interning).
  8. Explicit doc-note on the Ed25519->X25519 static key conversion: this
     implementation supports it for compatibility with DID keys that are
     Ed25519 only, but reusing a signing key as a DH key is a pattern the
     Noise spec authors and most cryptographers advise against unless you
     control both ends and understand the domain-separation argument (the
     conversion here hashes the seed with SHA-512 before deriving the X25519
     scalar, which is the standard/safe construction used by libsodium's
     crypto_sign_ed25519_sk_to_curve25519 — but a dedicated, independently
     generated X25519 static key is still the better default when you have
     the choice).

Nothing here is a substitute for an independent security review / audit
before production deployment. In particular: get this reviewed by someone
who does not work on it, and consider formal test vectors from the Noise
spec's test suite before shipping.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import logging
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logger = logging.getLogger(__name__)


# ============================================================================
# Exceptions
# ============================================================================

class NoiseError(Exception):
    """Base class for all Noise protocol errors."""


class NoiseHandshakeError(NoiseError):
    """Raised for protocol-usage errors (wrong step, already complete, etc.)."""


class NoiseAuthenticationError(NoiseError):
    """Raised when AEAD decryption / authentication fails.

    This can mean tampering, a MITM attempt, corrupted transport, or the
    wrong key. Do not use the string contents of this exception to make
    security decisions beyond "this message is not trustworthy" — do not
    log ciphertext or key material.
    """


class NoiseInvalidPublicKeyError(NoiseError):
    """Raised when a received public key is malformed or a low-order point
    that would produce a known/predictable DH shared secret."""


class NonceExhaustionError(NoiseError):
    """Raised when a CipherState's nonce space is exhausted and a rekey or
    new handshake is required."""


class MessageSizeError(NoiseError):
    """Raised when a message exceeds the Noise protocol's 65535-byte limit,
    or a received message is too short to contain the expected fields."""


# ============================================================================
# Constants per Noise Protocol Specification
# ============================================================================

class NoiseConstants:
    """Constants defined by the Noise Protocol Framework."""

    PROTOCOL_NAME = b"Noise_IK_25519_ChaChaPoly_SHA256"

    DHLEN = 32
    HASHLEN = 32
    SYMMETRIC_KEY_LEN = 32
    NONCE_LEN = 12
    TAG_LEN = 16

    # Nonce value reserved by REKEY(); MUST NOT be used for a normal message.
    REKEY_NONCE = 2 ** 64 - 1
    # Largest nonce usable by a normal (non-rekey) message.
    MAX_MESSAGE_NONCE = REKEY_NONCE - 1

    # Every Noise message (handshake or transport) is capped at this size.
    MAX_MESSAGE_LEN = 65535

    EMPTY_KEY = b"\x00" * SYMMETRIC_KEY_LEN

    HANDSHAKE_IK = [
        [b"e", b"es", b"s", b"ss"],  # Initiator -> Responder
        [b"e", b"ee", b"se"],        # Responder -> Initiator
    ]


def _zero(buf: Optional[bytearray]) -> None:
    """Best-effort zeroing of a mutable buffer.

    CPython gives no hard guarantee this fully scrubs every copy of the
    data from memory (immutable `bytes` objects in particular cannot be
    zeroed at all — this only helps for `bytearray`s we control). Treat
    this as defense-in-depth, not a guarantee.
    """
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0


# ============================================================================
# Noise Crypto Functions (per spec Section 4)
# ============================================================================

class NoiseCrypto:
    """Cryptographic primitives for the Noise Protocol."""

    @staticmethod
    def generate_keypair() -> x25519.X25519PrivateKey:
        return x25519.X25519PrivateKey.generate()

    @staticmethod
    def dh(private_key: x25519.X25519PrivateKey,
           public_key: x25519.X25519PublicKey) -> bytes:
        """DH(key_pair, public_key) with a check against low-order /
        all-zero outputs (rogue-key / small-subgroup defense, spec §9)."""
        shared = private_key.exchange(public_key)
        # X25519 exchange with a small-order or otherwise degenerate public
        # key can yield an all-zero shared secret. Reject it rather than
        # silently mixing a known value into the key schedule.
        if hmac_module.compare_digest(shared, b"\x00" * NoiseConstants.DHLEN):
            raise NoiseInvalidPublicKeyError(
                "DH produced an all-zero shared secret; the remote public "
                "key is invalid or low-order (possible rogue-key attempt)."
            )
        return shared

    @staticmethod
    def encrypt(k: bytes, n: int, ad: bytes, plaintext: bytes) -> bytes:
        """ENCRYPT(k, n, ad, plaintext). `n` must be < REKEY_NONCE unless
        this call originates from CipherState.rekey()."""
        if n > NoiseConstants.REKEY_NONCE:
            raise NonceExhaustionError("Nonce space exhausted.")
        if len(plaintext) > NoiseConstants.MAX_MESSAGE_LEN - NoiseConstants.TAG_LEN:
            raise MessageSizeError("Plaintext too large for a single Noise message.")

        nonce = struct.pack("<Q", n).rjust(12, b"\x00")
        cipher = ChaCha20Poly1305(k)
        return cipher.encrypt(nonce, plaintext, ad)

    @staticmethod
    def decrypt(k: bytes, n: int, ad: bytes, ciphertext: bytes) -> bytes:
        if n > NoiseConstants.REKEY_NONCE:
            raise NonceExhaustionError("Nonce space exhausted.")
        if len(ciphertext) > NoiseConstants.MAX_MESSAGE_LEN:
            raise MessageSizeError("Ciphertext exceeds the maximum Noise message size.")

        nonce = struct.pack("<Q", n).rjust(12, b"\x00")
        cipher = ChaCha20Poly1305(k)
        try:
            return cipher.decrypt(nonce, ciphertext, ad)
        except InvalidTag as exc:
            raise NoiseAuthenticationError(
                "AEAD authentication failed (tampering, wrong key, or corrupted data)."
            ) from exc

    @staticmethod
    def hash(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def hkdf(chaining_key: bytes, input_key_material: bytes, num_outputs: int = 2) -> List[bytes]:
        if num_outputs < 1 or num_outputs > 3:
            raise ValueError("num_outputs must be 1, 2, or 3")

        temp_key = hmac_module.new(chaining_key, input_key_material, hashlib.sha256).digest()

        outputs: List[bytes] = []
        output = b""
        for i in range(num_outputs):
            output = hmac_module.new(temp_key, output + bytes([i + 1]), hashlib.sha256).digest()
            outputs.append(output)
        return outputs

    @staticmethod
    def ed25519_to_x25519_private(ed_private: ed25519.Ed25519PrivateKey) -> x25519.X25519PrivateKey:
        """Convert an Ed25519 private key to X25519 (libsodium-compatible
        construction: SHA-512(seed), take low 32 bytes, clamp).

        See the module docstring for a note on the tradeoffs of reusing a
        signing key for DH instead of using an independent X25519 key.
        """
        ed_bytes = ed_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        hashed = bytearray(hashlib.sha512(ed_bytes).digest())
        try:
            x25519_key = bytearray(hashed[:32])
            x25519_key[0] &= 248
            x25519_key[31] &= 127
            x25519_key[31] |= 64
            return x25519.X25519PrivateKey.from_private_bytes(bytes(x25519_key))
        finally:
            _zero(hashed)

    @staticmethod
    def ed25519_to_x25519_public(ed_public: ed25519.Ed25519PublicKey) -> x25519.X25519PublicKey:
        """Convert an Ed25519 public key to X25519 via the standard
        birational map between Edwards25519 and Curve25519: u = (1+y)/(1-y) mod p.
        """
        ed_bytes = ed_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if len(ed_bytes) != 32:
            raise NoiseInvalidPublicKeyError("Ed25519 public key must be 32 bytes.")

        p = 2 ** 255 - 19

        y_bytes = bytearray(ed_bytes)
        y_bytes[31] &= 0x7F  # clear the sign bit; irrelevant to the u-coordinate
        y = int.from_bytes(bytes(y_bytes), "little")
        if y >= p:
            raise NoiseInvalidPublicKeyError("Invalid Ed25519 public key encoding (y >= p).")

        numerator = (1 + y) % p
        denominator = (1 - y) % p
        if denominator == 0:
            # y == 1 corresponds to the identity point; there is no valid
            # Montgomery u-coordinate for it.
            raise NoiseInvalidPublicKeyError(
                "Ed25519 public key maps to the identity point; cannot convert to X25519."
            )

        u = (numerator * pow(denominator, p - 2, p)) % p
        return x25519.X25519PublicKey.from_public_bytes(u.to_bytes(32, "little"))

    @staticmethod
    def x25519_public_bytes(key: Union[x25519.X25519PublicKey, x25519.X25519PrivateKey]) -> bytes:
        if isinstance(key, x25519.X25519PrivateKey):
            key = key.public_key()
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


# ============================================================================
# CipherState (per spec Section 5)
# ============================================================================

class CipherState:
    """CipherState for encrypting/decrypting transport (or handshake) messages."""

    def __init__(self):
        self.k: bytes = NoiseConstants.EMPTY_KEY
        self.n: int = 0

    def initialize_key(self, key: bytes) -> None:
        if len(key) != NoiseConstants.SYMMETRIC_KEY_LEN:
            raise ValueError(f"Key must be {NoiseConstants.SYMMETRIC_KEY_LEN} bytes")
        self.k = key
        self.n = 0

    def has_key(self) -> bool:
        return not hmac_module.compare_digest(self.k, NoiseConstants.EMPTY_KEY)

    def set_nonce(self, nonce: int) -> None:
        self.n = nonce

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if not self.has_key():
            return plaintext
        if self.n > NoiseConstants.MAX_MESSAGE_NONCE:
            raise NonceExhaustionError(
                "Sending nonce space exhausted; rekey or start a new session."
            )
        ciphertext = NoiseCrypto.encrypt(self.k, self.n, ad, plaintext)
        self.n += 1
        return ciphertext

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if not self.has_key():
            return ciphertext
        if self.n > NoiseConstants.MAX_MESSAGE_NONCE:
            raise NonceExhaustionError(
                "Receiving nonce space exhausted; rekey or start a new session."
            )
        plaintext = NoiseCrypto.decrypt(self.k, self.n, ad, ciphertext)
        self.n += 1
        return plaintext

    def rekey(self) -> None:
        """k = REKEY(k) = first 32 bytes of ENCRYPT(k, 2**64-1, '', zeros(32))."""
        new_k = NoiseCrypto.encrypt(
            self.k, NoiseConstants.REKEY_NONCE, b"", b"\x00" * NoiseConstants.SYMMETRIC_KEY_LEN
        )[:NoiseConstants.SYMMETRIC_KEY_LEN]
        old_k = bytearray(self.k)
        self.k = new_k
        _zero(old_k)


# ============================================================================
# SymmetricState (per spec Section 6)
# ============================================================================

class SymmetricState:
    """SymmetricState for handshake processing."""

    def __init__(self, protocol_name: bytes):
        self.cipher_state = CipherState()
        self.ck: bytes = b""
        self.h: bytes = b""
        self._initialize_symmetric(protocol_name)

    def _initialize_symmetric(self, protocol_name: bytes) -> None:
        if len(protocol_name) <= NoiseConstants.HASHLEN:
            self.h = protocol_name + b"\x00" * (NoiseConstants.HASHLEN - len(protocol_name))
        else:
            self.h = NoiseCrypto.hash(protocol_name)
        self.ck = self.h
        self.cipher_state = CipherState()

    def mix_key(self, input_key_material: bytes) -> None:
        outputs = NoiseCrypto.hkdf(self.ck, input_key_material, 2)
        self.ck = outputs[0]
        if self.cipher_state.has_key():
            self.cipher_state = CipherState()
        self.cipher_state.initialize_key(outputs[1])

    def mix_hash(self, data: bytes) -> None:
        self.h = NoiseCrypto.hash(self.h + data)

    def mix_key_and_hash(self, input_key_material: bytes) -> None:
        """For PSK-augmented patterns; unused by plain Noise_IK but kept
        for API completeness / forward compatibility."""
        outputs = NoiseCrypto.hkdf(self.ck, input_key_material, 3)
        self.ck = outputs[0]
        self.mix_hash(outputs[1])
        if self.cipher_state.has_key():
            self.cipher_state = CipherState()
        self.cipher_state.initialize_key(outputs[2])

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher_state.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher_state.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> Tuple[CipherState, CipherState]:
        outputs = NoiseCrypto.hkdf(self.ck, b"", 2)
        c1, c2 = CipherState(), CipherState()
        c1.initialize_key(outputs[0])
        c2.initialize_key(outputs[1])
        return c1, c2


# ============================================================================
# HandshakeState (per spec Section 7)
# ============================================================================

class NoiseHandshake:
    """Noise HandshakeState implementing the IK pattern."""

    def __init__(self):
        self.symmetric_state: Optional[SymmetricState] = None
        self.s: Optional[x25519.X25519PrivateKey] = None
        self.e: Optional[x25519.X25519PrivateKey] = None
        self.rs: Optional[x25519.X25519PublicKey] = None
        self.re: Optional[x25519.X25519PublicKey] = None
        self.initiator: bool = False
        self.message_patterns: List[List[bytes]] = []
        self.step: int = 0
        self._handshake_complete: bool = False

        self.send_cipher: Optional[CipherState] = None
        self.recv_cipher: Optional[CipherState] = None

        self.local_ed25519: Optional[ed25519.Ed25519PrivateKey] = None
        self.remote_ed25519: Optional[ed25519.Ed25519PublicKey] = None
        self.session_id: str = ""
        self.handshake_hash: bytes = b""
        self.prologue: bytes = b""

    # -- key conversion helpers ------------------------------------------------
    @staticmethod
    def _ed25519_to_x25519_private(ed_key: ed25519.Ed25519PrivateKey) -> x25519.X25519PrivateKey:
        return NoiseCrypto.ed25519_to_x25519_private(ed_key)

    @staticmethod
    def _ed25519_to_x25519_public(ed_key: ed25519.Ed25519PublicKey) -> x25519.X25519PublicKey:
        return NoiseCrypto.ed25519_to_x25519_public(ed_key)

    @staticmethod
    def _x25519_public_bytes(key: Union[x25519.X25519PublicKey, x25519.X25519PrivateKey]) -> bytes:
        return NoiseCrypto.x25519_public_bytes(key)

    # -- initialization ----------------------------------------------------
    def initialize_initiator(self,
                              local_ed25519: ed25519.Ed25519PrivateKey,
                              remote_ed25519: ed25519.Ed25519PublicKey,
                              prologue: bytes = b"",
                              session_id: str = "") -> None:
        self.initiator = True
        self.local_ed25519 = local_ed25519
        self.remote_ed25519 = remote_ed25519
        self.prologue = prologue
        self.session_id = session_id or secrets.token_hex(16)

        self.s = self._ed25519_to_x25519_private(local_ed25519)
        self.rs = self._ed25519_to_x25519_public(remote_ed25519)

        self.symmetric_state = SymmetricState(NoiseConstants.PROTOCOL_NAME)
        if prologue:
            self.symmetric_state.mix_hash(prologue)

        rs_bytes = self._x25519_public_bytes(self.rs)
        self.symmetric_state.mix_hash(rs_bytes)

        self.message_patterns = NoiseConstants.HANDSHAKE_IK
        self.step = 0
        self._handshake_complete = False
        logger.debug("Initiator handshake initialized: session=%s", self.session_id)

    def initialize_responder(self,
                              local_ed25519: ed25519.Ed25519PrivateKey,
                              prologue: bytes = b"",
                              session_id: str = "") -> None:
        self.initiator = False
        self.local_ed25519 = local_ed25519
        self.remote_ed25519 = None
        self.prologue = prologue
        self.session_id = session_id or secrets.token_hex(16)

        self.s = self._ed25519_to_x25519_private(local_ed25519)
        self.rs = None

        self.symmetric_state = SymmetricState(NoiseConstants.PROTOCOL_NAME)
        if prologue:
            self.symmetric_state.mix_hash(prologue)

        s_bytes = self._x25519_public_bytes(self.s)
        self.symmetric_state.mix_hash(s_bytes)

        self.message_patterns = NoiseConstants.HANDSHAKE_IK
        self.step = 0
        self._handshake_complete = False
        logger.debug("Responder handshake initialized: session=%s", self.session_id)

    # -- write / read --------------------------------------------------------
    def write_message(self, payload: bytes = b"") -> bytes:
        if self._handshake_complete:
            raise NoiseHandshakeError("Handshake already complete - use transport messages")
        if self.step >= len(self.message_patterns):
            raise NoiseHandshakeError("No more handshake messages to write")
        if len(payload) > NoiseConstants.MAX_MESSAGE_LEN:
            raise MessageSizeError("Handshake payload too large.")

        tokens = self.message_patterns[self.step]
        message_buffer = bytearray()

        logger.debug("Writing handshake message: step=%d tokens=%s", self.step, tokens)

        for token in tokens:
            if token == b"e":
                self.e = NoiseCrypto.generate_keypair()
                e_bytes = self._x25519_public_bytes(self.e)
                message_buffer.extend(e_bytes)
                self.symmetric_state.mix_hash(e_bytes)

            elif token == b"s":
                if self.s is None:
                    raise NoiseHandshakeError("Local static key not set.")
                s_bytes = self._x25519_public_bytes(self.s)
                encrypted_s = self.symmetric_state.encrypt_and_hash(s_bytes)
                message_buffer.extend(encrypted_s)

            elif token == b"es":
                if self.initiator:
                    dh_output = NoiseCrypto.dh(self.e, self.rs)
                else:
                    dh_output = NoiseCrypto.dh(self.s, self.re)
                self.symmetric_state.mix_key(dh_output)

            elif token == b"ss":
                dh_output = NoiseCrypto.dh(self.s, self.rs)
                self.symmetric_state.mix_key(dh_output)

            elif token == b"ee":
                dh_output = NoiseCrypto.dh(self.e, self.re)
                self.symmetric_state.mix_key(dh_output)

            elif token == b"se":
                if self.initiator:
                    dh_output = NoiseCrypto.dh(self.s, self.re)
                else:
                    dh_output = NoiseCrypto.dh(self.e, self.rs)
                self.symmetric_state.mix_key(dh_output)

            else:
                raise NoiseHandshakeError(f"Unknown token: {token!r}")

        if payload:
            encrypted_payload = self.symmetric_state.encrypt_and_hash(payload)
            message_buffer.extend(encrypted_payload)

        if len(message_buffer) > NoiseConstants.MAX_MESSAGE_LEN:
            raise MessageSizeError("Assembled handshake message exceeds 65535 bytes.")

        self.handshake_hash = self.symmetric_state.h
        self.step += 1

        if self.step >= len(self.message_patterns):
            logger.debug("Handshake complete - splitting into transport cipher states")
            self.send_cipher, self.recv_cipher = self.symmetric_state.split()
            if not self.initiator:
                self.send_cipher, self.recv_cipher = self.recv_cipher, self.send_cipher
            self._handshake_complete = True
            self._clear_ephemeral()

        return bytes(message_buffer)

    def read_message(self, message: bytes) -> bytes:
        if self._handshake_complete:
            raise NoiseHandshakeError("Handshake already complete - use transport messages")
        if self.step >= len(self.message_patterns):
            raise NoiseHandshakeError("No more handshake messages to read")
        if len(message) > NoiseConstants.MAX_MESSAGE_LEN:
            raise MessageSizeError("Received handshake message exceeds 65535 bytes.")

        tokens = self.message_patterns[self.step]
        offset = 0

        logger.debug("Reading handshake message: step=%d tokens=%s", self.step, tokens)

        for token in tokens:
            if token == b"e":
                if offset + NoiseConstants.DHLEN > len(message):
                    raise MessageSizeError("Message too short: expected ephemeral key")
                re_bytes = message[offset:offset + NoiseConstants.DHLEN]
                offset += NoiseConstants.DHLEN
                try:
                    self.re = x25519.X25519PublicKey.from_public_bytes(re_bytes)
                except ValueError as exc:
                    raise NoiseInvalidPublicKeyError("Malformed ephemeral public key.") from exc
                self.symmetric_state.mix_hash(re_bytes)

            elif token == b"s":
                encrypted_len = (
                    NoiseConstants.DHLEN + NoiseConstants.TAG_LEN
                    if self.symmetric_state.cipher_state.has_key()
                    else NoiseConstants.DHLEN
                )
                if offset + encrypted_len > len(message):
                    raise MessageSizeError("Message too short: expected static key")
                encrypted_s = message[offset:offset + encrypted_len]
                offset += encrypted_len

                s_bytes = self.symmetric_state.decrypt_and_hash(encrypted_s)
                if len(s_bytes) != NoiseConstants.DHLEN:
                    raise NoiseInvalidPublicKeyError(f"Invalid static key length: {len(s_bytes)}")
                try:
                    self.rs = x25519.X25519PublicKey.from_public_bytes(s_bytes)
                except ValueError as exc:
                    raise NoiseInvalidPublicKeyError("Malformed remote static key.") from exc

            elif token == b"es":
                if self.initiator:
                    if not self.rs:
                        raise NoiseHandshakeError("Remote static key not available")
                    dh_output = NoiseCrypto.dh(self.e, self.rs)
                else:
                    if not self.re:
                        raise NoiseHandshakeError("Remote ephemeral key not available")
                    dh_output = NoiseCrypto.dh(self.s, self.re)
                self.symmetric_state.mix_key(dh_output)

            elif token == b"ss":
                if not self.rs:
                    raise NoiseHandshakeError("Remote static key not available")
                dh_output = NoiseCrypto.dh(self.s, self.rs)
                self.symmetric_state.mix_key(dh_output)

            elif token == b"ee":
                if not self.e or not self.re:
                    raise NoiseHandshakeError("Ephemeral keys not available")
                dh_output = NoiseCrypto.dh(self.e, self.re)
                self.symmetric_state.mix_key(dh_output)

            elif token == b"se":
                if self.initiator:
                    if not self.re:
                        raise NoiseHandshakeError("Remote ephemeral key not available")
                    dh_output = NoiseCrypto.dh(self.s, self.re)
                else:
                    if not self.rs:
                        raise NoiseHandshakeError("Remote static key not available")
                    dh_output = NoiseCrypto.dh(self.e, self.rs)
                self.symmetric_state.mix_key(dh_output)

            else:
                raise NoiseHandshakeError(f"Unknown token: {token!r}")

        remaining = len(message) - offset
        if remaining > 0:
            if remaining < NoiseConstants.TAG_LEN and self.symmetric_state.cipher_state.has_key():
                raise MessageSizeError("Message too short: encrypted payload too small")
            encrypted_payload = message[offset:]
            payload = self.symmetric_state.decrypt_and_hash(encrypted_payload)
        else:
            payload = b""

        self.handshake_hash = self.symmetric_state.h
        self.step += 1

        if self.step >= len(self.message_patterns):
            logger.debug("Handshake complete - splitting into transport cipher states")
            self.send_cipher, self.recv_cipher = self.symmetric_state.split()
            if not self.initiator:
                self.send_cipher, self.recv_cipher = self.recv_cipher, self.send_cipher
            self._handshake_complete = True
            self._clear_ephemeral()

        return payload

    def _clear_ephemeral(self) -> None:
        """Best-effort: drop the reference to our ephemeral private key once
        it's no longer needed, so it can be garbage collected promptly.
        (cryptography's key objects don't expose in-place zeroing.)
        """
        self.e = None

    # -- transport phase ------------------------------------------------------
    def is_handshake_complete(self) -> bool:
        return self._handshake_complete

    def send_transport(self, payload: bytes) -> bytes:
        if not self._handshake_complete:
            raise NoiseHandshakeError("Handshake not complete")
        return self.send_cipher.encrypt_with_ad(b"", payload)

    def recv_transport(self, message: bytes) -> bytes:
        if not self._handshake_complete:
            raise NoiseHandshakeError("Handshake not complete")
        return self.recv_cipher.decrypt_with_ad(b"", message)

    def rekey_send(self) -> None:
        if self.send_cipher:
            self.send_cipher.rekey()

    def rekey_recv(self) -> None:
        if self.recv_cipher:
            self.recv_cipher.rekey()

    # -- utilities --------------------------------------------------------
    def get_handshake_hash(self) -> bytes:
        return self.handshake_hash

    def get_session_key(self) -> bytes:
        if self.send_cipher:
            return self.send_cipher.k
        raise NoiseHandshakeError("No transport cipher initialized")


# ============================================================================
# Noise Session Manager
# ============================================================================

@dataclass
class NoiseSession:
    session_id: str
    handshake: NoiseHandshake
    local_did: str
    remote_did: str
    initiator: bool
    established_at: float = field(default_factory=time.time)
    handshake_hash: bytes = b""
    last_activity: float = field(default_factory=time.time)

    def encrypt(self, plaintext: Union[str, bytes]) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        self.last_activity = time.time()
        return self.handshake.send_transport(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        self.last_activity = time.time()
        return self.handshake.recv_transport(ciphertext)


class NoiseSessionManager:
    """Manage multiple Noise sessions. Thread-safe."""

    def __init__(self):
        self.sessions: Dict[str, NoiseSession] = {}
        self.pending_handshakes: Dict[str, NoiseHandshake] = {}
        self._lock = threading.RLock()

    def create_initiator_handshake(self,
                                    local_did: str,
                                    remote_did: str,
                                    local_ed25519: ed25519.Ed25519PrivateKey,
                                    remote_ed25519: ed25519.Ed25519PublicKey,
                                    prologue: bytes = b"") -> Tuple[str, bytes]:
        session_id = secrets.token_hex(16)

        handshake = NoiseHandshake()
        handshake.initialize_initiator(
            local_ed25519=local_ed25519,
            remote_ed25519=remote_ed25519,
            prologue=prologue,
            session_id=session_id,
        )
        message = handshake.write_message()

        with self._lock:
            self.pending_handshakes[session_id] = handshake

        return session_id, message

    def handle_response(self,
                         session_id: str,
                         response_message: bytes,
                         local_did: str,
                         remote_did: str) -> NoiseSession:
        with self._lock:
            handshake = self.pending_handshakes.pop(session_id, None)
        if handshake is None:
            raise NoiseHandshakeError(f"Unknown session: {session_id}")

        handshake.read_message(response_message)

        session = NoiseSession(
            session_id=session_id,
            handshake=handshake,
            local_did=local_did,
            remote_did=remote_did,
            initiator=True,
        )
        session.handshake_hash = handshake.get_handshake_hash()

        with self._lock:
            self.sessions[session_id] = session
        return session

    def handle_initiation(self,
                           init_message: bytes,
                           local_did: str,
                           local_ed25519: ed25519.Ed25519PrivateKey,
                           prologue: bytes = b"") -> Tuple[str, bytes, str]:
        session_id = secrets.token_hex(16)

        handshake = NoiseHandshake()
        handshake.initialize_responder(
            local_ed25519=local_ed25519,
            prologue=prologue,
            session_id=session_id,
        )
        handshake.read_message(init_message)
        response = handshake.write_message()

        # The remote party's DID must be resolved out-of-band (e.g. from the
        # transport address, an application-layer identifier in the
        # payload, or by matching handshake.rs against known DID documents)
        # and supplied by the caller — it is not implied by the handshake.
        remote_did = "unknown"

        session = NoiseSession(
            session_id=session_id,
            handshake=handshake,
            local_did=local_did,
            remote_did=remote_did,
            initiator=False,
        )
        session.handshake_hash = handshake.get_handshake_hash()

        with self._lock:
            self.sessions[session_id] = session
        return session_id, response, remote_did

    def get_session(self, session_id: str) -> Optional[NoiseSession]:
        with self._lock:
            return self.sessions.get(session_id)

    def remove_session(self, session_id: str) -> None:
        with self._lock:
            self.sessions.pop(session_id, None)
            self.pending_handshakes.pop(session_id, None)

    def cleanup_expired_sessions(self, max_age: float = 3600) -> None:
        now = time.time()
        with self._lock:
            expired = [
                sid for sid, session in self.sessions.items()
                if now - session.last_activity > max_age
            ]
            for sid in expired:
                self.remove_session(sid)


# ============================================================================
# Integration with UDNA DID Resolution
# ============================================================================

class UdnaNoiseIntegration:
    """Bridge between a DID system and the Noise Protocol."""

    @staticmethod
    def extract_static_key_from_did(did: "Did", did_document=None) -> ed25519.Ed25519PublicKey:
        from udna import DidKeyMethod  # local import: optional dependency

        if did.method == "key":
            doc = DidKeyMethod.resolve(did)
            raw_key = doc.get_public_key(doc.authentication[0])
            if raw_key is None:
                raise ValueError(f"Could not extract key from DID document: {did}")
            return ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
        else:
            if did_document:
                raw_key = did_document.get_public_key(did_document.authentication[0])
                if raw_key is None:
                    raise ValueError(f"Could not extract key from DID document: {did}")
                return ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
            raise ValueError(f"Cannot resolve DID method: {did.method}")

    @staticmethod
    def create_prologue(local_did: str, remote_did: str,
                         session_id: str, timestamp: int) -> bytes:
        """Bind the Noise session to specific DIDs and context so it can't
        be replayed/reused in a different context.

        Note: this prologue is mixed into the handshake hash and is
        authenticated as part of the transcript, but it is NOT itself
        secret — don't put anything sensitive in it.
        """
        return (
            local_did.encode() + b"|" +
            remote_did.encode() + b"|" +
            session_id.encode() + b"|" +
            struct.pack("!Q", timestamp)
        )

    @staticmethod
    def verify_session_binding(session: NoiseSession,
                                expected_local_did: str,
                                expected_remote_did: str) -> bool:
        return (
            hmac_module.compare_digest(session.local_did.encode(), expected_local_did.encode())
            and hmac_module.compare_digest(session.remote_did.encode(), expected_remote_did.encode())
        )


# ============================================================================
# Demo / smoke test
# ============================================================================

def demo_noise_protocol():
    """Runs a full handshake + transport exchange and checks the invariants
    that matter: both sides derive identical session keys and handshake
    hashes, and messages round-trip correctly. Not a substitute for the
    official Noise test vectors."""
    print("=" * 70)
    print("NOISE_IK_25519_ChaChaPoly_SHA256 — handshake + transport demo")
    print("=" * 70)

    alice_ed25519 = ed25519.Ed25519PrivateKey.generate()
    bob_ed25519 = ed25519.Ed25519PrivateKey.generate()
    bob_ed25519_pub = bob_ed25519.public_key()

    session_id = secrets.token_hex(16)
    timestamp = int(time.time())
    prologue = UdnaNoiseIntegration.create_prologue(
        "did:key:z6MkAlice", "did:key:z6MkBob", session_id, timestamp
    )

    alice_handshake = NoiseHandshake()
    alice_handshake.initialize_initiator(
        local_ed25519=alice_ed25519,
        remote_ed25519=bob_ed25519_pub,
        prologue=prologue,
        session_id=session_id,
    )
    message_1 = alice_handshake.write_message()
    print(f"1. Alice -> Bob: {len(message_1)} bytes")

    bob_handshake = NoiseHandshake()
    bob_handshake.initialize_responder(
        local_ed25519=bob_ed25519, prologue=prologue, session_id=session_id
    )
    bob_handshake.read_message(message_1)
    message_2 = bob_handshake.write_message(b"Hello Alice, I'm Bob!")
    print(f"2. Bob -> Alice: {len(message_2)} bytes (handshake complete: {bob_handshake.is_handshake_complete()})")

    payload_from_bob = alice_handshake.read_message(message_2)
    print(f"3. Alice decrypted Bob's payload: {payload_from_bob.decode()!r}")
    assert alice_handshake.is_handshake_complete()

    # Each direction gets its own key: Alice's send-key must equal Bob's
    # recv-key, and Alice's recv-key must equal Bob's send-key. (Comparing
    # "send == send" would be wrong -- they're intentionally different.)
    assert hmac_module.compare_digest(alice_handshake.send_cipher.k, bob_handshake.recv_cipher.k)
    assert hmac_module.compare_digest(alice_handshake.recv_cipher.k, bob_handshake.send_cipher.k)
    alice_key = alice_handshake.get_session_key()
    print("4. Per-direction transport keys match:", True)

    alice_pt = b"Hello Bob! This message is encrypted with the Noise protocol."
    ct = alice_handshake.send_transport(alice_pt)
    pt = bob_handshake.recv_transport(ct)
    assert pt == alice_pt
    print("5. Alice -> Bob transport round-trip OK")

    bob_pt = b"Hi Alice! Noise is working."
    ct2 = bob_handshake.send_transport(bob_pt)
    pt2 = alice_handshake.recv_transport(ct2)
    assert pt2 == bob_pt
    print("6. Bob -> Alice transport round-trip OK")

    assert hmac_module.compare_digest(
        alice_handshake.get_handshake_hash(), bob_handshake.get_handshake_hash()
    )
    print("7. Handshake hashes (channel binding) match:", True)

    # Tamper test: flipping a ciphertext byte must raise, not silently succeed.
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    try:
        bob_handshake2 = bob_handshake  # nonce already advanced; use a fresh check instead
        NoiseCrypto.decrypt(bob_handshake.recv_cipher.k, 0, b"", bytes(tampered))
        raised = False
    except NoiseAuthenticationError:
        raised = True
    print("8. Tampered ciphertext correctly rejected:", raised)

    print("=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)

    return {
        "alice_handshake": alice_handshake,
        "bob_handshake": bob_handshake,
        "session_key": alice_key,
        "handshake_hash": alice_handshake.get_handshake_hash(),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    demo_noise_protocol()