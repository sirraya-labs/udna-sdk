#!/usr/bin/env python3
"""
Test 1: Cryptographic Primitives (Verbose)
Shows all outputs and intermediate values for inspection.
"""

import sys
import secrets
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from noise_protocol import (
    NoiseConstants,
    NoiseCrypto,
    NoiseAuthenticationError,
    NonceExhaustionError,
)


class TestResult:
    """Simple test tracker with verbose output."""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
        self.test_num = 0
    
    def check(self, condition, message, detail=""):
        self.test_num += 1
        if condition:
            self.passed += 1
            print(f"  [{self.test_num}] ✓ {message}")
            if detail:
                print(f"       {detail}")
        else:
            self.failed += 1
            self.errors.append(message)
            print(f"  [{self.test_num}] ✗ FAILED: {message}")
    
    def check_raises(self, exception_type, func, *args, message=""):
        self.test_num += 1
        try:
            func(*args)
            self.failed += 1
            print(f"  [{self.test_num}] ✗ FAILED: Expected {exception_type.__name__} - {message}")
        except exception_type:
            self.passed += 1
            print(f"  [{self.test_num}] ✓ Correctly raised {exception_type.__name__}: {message}")
        except Exception as e:
            self.failed += 1
            print(f"  [{self.test_num}] ✗ FAILED: Expected {exception_type.__name__}, got {type(e).__name__}: {e}")
    
    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*70}")
        print(f"Test 1 Summary: {self.passed}/{total} passed")
        if self.failed:
            print("Failures:")
            for e in self.errors:
                print(f"  - {e}")
        print(f"{'='*70}")
        return self.failed == 0


def main():
    print("=" * 70)
    print("TEST 1: CRYPTOGRAPHIC PRIMITIVES (VERBOSE)")
    print(f"Protocol: {NoiseConstants.PROTOCOL_NAME.decode()}")
    print("=" * 70)
    
    result = TestResult()
    
    # ========================================================================
    # 1. Key Generation
    # ========================================================================
    print("\n" + "-" * 70)
    print("1. KEY GENERATION (X25519)")
    print("-" * 70)
    
    keypair = NoiseCrypto.generate_keypair()
    print(f"  Generated X25519 private key: {type(keypair).__name__}")
    result.check(keypair is not None, "X25519 keypair generation returns a key")
    result.check(
        isinstance(keypair, x25519.X25519PrivateKey),
        "Generated keypair is X25519PrivateKey"
    )
    
    pub_bytes = NoiseCrypto.x25519_public_bytes(keypair)
    print(f"  Public key bytes (hex): {pub_bytes.hex()}")
    print(f"  Public key length: {len(pub_bytes)} bytes")
    result.check(len(pub_bytes) == 32, "Public key is 32 bytes")
    
    pub_from_pub = NoiseCrypto.x25519_public_bytes(keypair.public_key())
    result.check(pub_bytes == pub_from_pub, "Public key extraction is consistent")
    
    keypair2 = NoiseCrypto.generate_keypair()
    pub_bytes2 = NoiseCrypto.x25519_public_bytes(keypair2)
    print(f"  Second public key (hex): {pub_bytes2.hex()}")
    result.check(pub_bytes != pub_bytes2, "Different keypairs produce different public keys")
    
    # ========================================================================
    # 2. Hash Function
    # ========================================================================
    print("\n" + "-" * 70)
    print("2. HASH FUNCTION (SHA256)")
    print("-" * 70)
    
    msg1 = b"test message"
    msg2 = b"different message"
    
    hash1 = NoiseCrypto.hash(msg1)
    hash2 = NoiseCrypto.hash(msg1)
    hash3 = NoiseCrypto.hash(msg2)
    
    print(f"  Input 1: {msg1!r}")
    print(f"  Hash 1:  {hash1.hex()}")
    print(f"  Hash 2 (same input): {hash2.hex()}")
    print(f"  Input 2: {msg2!r}")
    print(f"  Hash 3:  {hash3.hex()}")
    
    result.check(len(hash1) == 32, "SHA256 output is 32 bytes")
    result.check(hash1 == hash2, "Hash is deterministic (same input = same output)")
    result.check(hash1 != hash3, "Different inputs produce different hashes")
    
    empty_hash = NoiseCrypto.hash(b"")
    print(f"  Empty input hash: {empty_hash.hex()}")
    result.check(len(empty_hash) == 32, "Empty string hash is also 32 bytes")
    
    # ========================================================================
    # 3. HKDF
    # ========================================================================
    print("\n" + "-" * 70)
    print("3. HKDF (HMAC-based Key Derivation)")
    print("-" * 70)
    
    chain_key = b"chain_key_32_bytes____________"
    input_material = b"input_material_32_bytes______"
    
    print(f"  Chaining key: {chain_key!r}")
    print(f"  Input material: {input_material!r}")
    
    outputs = NoiseCrypto.hkdf(chain_key, input_material, 2)
    print(f"  HKDF output 1: {outputs[0].hex()}")
    print(f"  HKDF output 2: {outputs[1].hex()}")
    
    result.check(len(outputs) == 2, "HKDF with num_outputs=2 returns 2 outputs")
    result.check(len(outputs[0]) == 32, "First HKDF output is 32 bytes")
    result.check(len(outputs[1]) == 32, "Second HKDF output is 32 bytes")
    result.check(outputs[0] != outputs[1], "Two HKDF outputs are different from each other")
    
    # Determinism
    outputs2 = NoiseCrypto.hkdf(chain_key, input_material, 2)
    result.check(outputs[0] == outputs2[0], "HKDF is deterministic (same chain key + input)")
    result.check(outputs[1] == outputs2[1], "HKDF second output also deterministic")
    
    # Different chain key
    different_chain = b"different_chain_key_32_bytes__"
    outputs3 = NoiseCrypto.hkdf(different_chain, input_material, 2)
    print(f"  Different chain key output: {outputs3[0].hex()}")
    result.check(outputs[0] != outputs3[0], "Different chain key produces different output")
    
    # Different input material
    different_input = b"different_input_material_32_byt"
    outputs4 = NoiseCrypto.hkdf(chain_key, different_input, 2)
    print(f"  Different input output: {outputs4[0].hex()}")
    result.check(outputs[0] != outputs4[0], "Different input material produces different output")
    
    # 1 output
    output1 = NoiseCrypto.hkdf(chain_key, input_material, 1)
    print(f"  Single HKDF output: {output1[0].hex()}")
    result.check(len(output1) == 1, "HKDF with num_outputs=1 returns 1 output")
    result.check(len(output1[0]) == 32, "Single HKDF output is 32 bytes")
    
    # 3 outputs
    output3 = NoiseCrypto.hkdf(chain_key, input_material, 3)
    print(f"  Three HKDF outputs:")
    for i, o in enumerate(output3):
        print(f"    [{i}]: {o.hex()}")
    result.check(len(output3) == 3, "HKDF with num_outputs=3 returns 3 outputs")
    result.check(len(output3[2]) == 32, "Third HKDF output is 32 bytes")
    
    # Invalid num_outputs
    try:
        NoiseCrypto.hkdf(chain_key, input_material, 0)
        result.check(False, "HKDF with num_outputs=0 should raise ValueError")
    except ValueError as e:
        print(f"  num_outputs=0 raises: {e}")
        result.check(True, "HKDF with num_outputs=0 raises ValueError")
    
    try:
        NoiseCrypto.hkdf(chain_key, input_material, 4)
        result.check(False, "HKDF with num_outputs=4 should raise ValueError")
    except ValueError as e:
        print(f"  num_outputs=4 raises: {e}")
        result.check(True, "HKDF with num_outputs=4 raises ValueError")
    
    # ========================================================================
    # 4. Diffie-Hellman
    # ========================================================================
    print("\n" + "-" * 70)
    print("4. DIFFIE-HELLMAN (X25519)")
    print("-" * 70)
    
    alice = NoiseCrypto.generate_keypair()
    bob = NoiseCrypto.generate_keypair()
    
    print(f"  Alice public: {NoiseCrypto.x25519_public_bytes(alice).hex()}")
    print(f"  Bob public:   {NoiseCrypto.x25519_public_bytes(bob).hex()}")
    
    shared_alice = NoiseCrypto.dh(alice, bob.public_key())
    shared_bob = NoiseCrypto.dh(bob, alice.public_key())
    
    print(f"  Alice's shared secret: {shared_alice.hex()}")
    print(f"  Bob's shared secret:   {shared_bob.hex()}")
    
    result.check(len(shared_alice) == 32, "DH shared secret is 32 bytes")
    result.check(shared_alice == shared_bob, "DH produces identical shared secret both ways")
    result.check(shared_alice != b"\x00" * 32, "DH shared secret is not all zeros")
    
    charlie = NoiseCrypto.generate_keypair()
    shared_alice_charlie = NoiseCrypto.dh(alice, charlie.public_key())
    print(f"  Alice-Charlie shared:  {shared_alice_charlie.hex()}")
    result.check(shared_alice != shared_alice_charlie, "Different peers produce different shared secrets")
    
    # ========================================================================
    # 5. Encrypt / Decrypt
    # ========================================================================
    print("\n" + "-" * 70)
    print("5. ENCRYPT/DECRYPT (ChaCha20-Poly1305 AEAD)")
    print("-" * 70)
    
    key = secrets.token_bytes(32)
    nonce = 0
    ad = b"associated data"
    plaintext = b"Hello, Noise Protocol! This is a test message."
    
    print(f"  Key:     {key.hex()}")
    print(f"  Nonce:   {nonce}")
    print(f"  AD:      {ad!r}")
    print(f"  Plaintext ({len(plaintext)} bytes): {plaintext!r}")
    
    ciphertext = NoiseCrypto.encrypt(key, nonce, ad, plaintext)
    print(f"  Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")
    print(f"    - Encrypted data: {ciphertext[:-16].hex()}")
    print(f"    - Poly1305 tag:   {ciphertext[-16:].hex()}")
    
    result.check(len(ciphertext) == len(plaintext) + 16, "Ciphertext is plaintext + 16 bytes (Poly1305 tag)")
    result.check(ciphertext != plaintext, "Ciphertext differs from plaintext")
    
    decrypted = NoiseCrypto.decrypt(key, nonce, ad, ciphertext)
    print(f"  Decrypted: {decrypted!r}")
    result.check(decrypted == plaintext, "Decryption recovers original plaintext")
    
    # Different nonce
    ciphertext2 = NoiseCrypto.encrypt(key, 1, ad, plaintext)
    print(f"  With nonce=1: {ciphertext2.hex()[:40]}...")
    result.check(ciphertext != ciphertext2, "Different nonce produces different ciphertext")
    
    # Different AD
    ciphertext3 = NoiseCrypto.encrypt(key, nonce, b"different ad", plaintext)
    print(f"  With different AD: {ciphertext3.hex()[:40]}...")
    result.check(ciphertext != ciphertext3, "Different associated data produces different ciphertext")
    
    # Wrong key
    wrong_key = secrets.token_bytes(32)
    try:
        NoiseCrypto.decrypt(wrong_key, nonce, ad, ciphertext)
        result.check(False, "Wrong key should fail")
    except NoiseAuthenticationError as e:
        print(f"  Wrong key error: {e}")
        result.check(True, "Wrong key causes authentication failure")
    
    # Wrong nonce
    try:
        NoiseCrypto.decrypt(key, 99, ad, ciphertext)
        result.check(False, "Wrong nonce should fail")
    except NoiseAuthenticationError as e:
        print(f"  Wrong nonce error: {e}")
        result.check(True, "Wrong nonce causes authentication failure")
    
    # Wrong AD
    try:
        NoiseCrypto.decrypt(key, nonce, b"wrong ad", ciphertext)
        result.check(False, "Wrong AD should fail")
    except NoiseAuthenticationError as e:
        print(f"  Wrong AD error: {e}")
        result.check(True, "Wrong associated data causes authentication failure")
    
    # Tampered ciphertext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    try:
        NoiseCrypto.decrypt(key, nonce, ad, bytes(tampered))
        result.check(False, "Tampered ciphertext should fail")
    except NoiseAuthenticationError as e:
        print(f"  Tampered ciphertext error: {e}")
        result.check(True, "Tampered ciphertext causes authentication failure")
    
    # Tampered tag
    tampered_tag = bytearray(ciphertext)
    tampered_tag[-1] ^= 0xFF
    try:
        NoiseCrypto.decrypt(key, nonce, ad, bytes(tampered_tag))
        result.check(False, "Tampered tag should fail")
    except NoiseAuthenticationError as e:
        print(f"  Tampered tag error: {e}")
        result.check(True, "Tampered authentication tag causes failure")
    
    # Empty plaintext
    empty_ct = NoiseCrypto.encrypt(key, 0, ad, b"")
    print(f"  Empty plaintext ciphertext ({len(empty_ct)} bytes): {empty_ct.hex()}")
    result.check(len(empty_ct) == 16, "Empty plaintext produces only tag (16 bytes)")
    empty_pt = NoiseCrypto.decrypt(key, 0, ad, empty_ct)
    result.check(empty_pt == b"", "Empty plaintext round-trips correctly")
    
    # ========================================================================
    # 6. Nonce Exhaustion
    # ========================================================================
    print("\n" + "-" * 70)
    print("6. NONCE EXHAUSTION")
    print("-" * 70)
    
    print(f"  MAX_NONCE (reserved): {NoiseConstants.REKEY_NONCE} (2^64 - 1)")
    print(f"  MAX_MESSAGE_NONCE:     {NoiseConstants.MAX_MESSAGE_NONCE}")
    
    try:
        NoiseCrypto.encrypt(key, 2**64, ad, plaintext)
        result.check(False, "Nonce 2^64 should fail")
    except NonceExhaustionError as e:
        print(f"  Nonce 2^64 error: {e}")
        result.check(True, "Nonce 2^64 raises NonceExhaustionError")
    
    try:
        last_ct = NoiseCrypto.encrypt(key, 2**64 - 1, ad, plaintext)
        print(f"  Last valid nonce encrypt: {last_ct.hex()[:40]}...")
        result.check(True, "Nonce 2^64-1 (MAX_NONCE) works for encrypt")
    except NonceExhaustionError as e:
        print(f"  Unexpected error: {e}")
        result.check(False, "Nonce 2^64-1 should not raise NonceExhaustionError")
    
    # ========================================================================
    # 7. Ed25519 to X25519 Conversion
    # ========================================================================
    print("\n" + "-" * 70)
    print("7. Ed25519 TO X25519 KEY CONVERSION")
    print("-" * 70)
    
    ed_private = ed25519.Ed25519PrivateKey.generate()
    ed_public = ed_private.public_key()
    
    print(f"  Ed25519 private key type: {type(ed_private).__name__}")
    print(f"  Ed25519 public key (hex): {ed_public.public_bytes_raw().hex()}")
    
    x_private = NoiseCrypto.ed25519_to_x25519_private(ed_private)
    x_public = NoiseCrypto.ed25519_to_x25519_public(ed_public)
    
    x_pub_bytes = NoiseCrypto.x25519_public_bytes(x_private)
    x_pub_from_pub = NoiseCrypto.x25519_public_bytes(x_public)
    
    print(f"  X25519 private -> public: {x_pub_bytes.hex()}")
    print(f"  X25519 converted public:  {x_pub_from_pub.hex()}")
    
    result.check(isinstance(x_private, x25519.X25519PrivateKey), "Ed25519 private -> X25519 private conversion works")
    result.check(isinstance(x_public, x25519.X25519PublicKey), "Ed25519 public -> X25519 public conversion works")
    result.check(len(x_pub_bytes) == 32, "Converted public key is 32 bytes")
    
    # Determinism
    x_private2 = NoiseCrypto.ed25519_to_x25519_private(ed_private)
    x_pub2 = NoiseCrypto.x25519_public_bytes(x_private2)
    result.check(x_pub_bytes == x_pub2, "Ed25519->X25519 conversion is deterministic")
    
    # DH with converted keys
    alice_ed = ed25519.Ed25519PrivateKey.generate()
    bob_ed = ed25519.Ed25519PrivateKey.generate()
    
    alice_x = NoiseCrypto.ed25519_to_x25519_private(alice_ed)
    bob_x = NoiseCrypto.ed25519_to_x25519_private(bob_ed)
    
    print(f"\n  DH with converted keys:")
    print(f"  Alice X25519 public: {NoiseCrypto.x25519_public_bytes(alice_x).hex()}")
    print(f"  Bob X25519 public:   {NoiseCrypto.x25519_public_bytes(bob_x).hex()}")
    
    shared_alice = NoiseCrypto.dh(alice_x, bob_x.public_key())
    shared_bob = NoiseCrypto.dh(bob_x, alice_x.public_key())
    
    print(f"  Shared secret (Alice): {shared_alice.hex()}")
    print(f"  Shared secret (Bob):   {shared_bob.hex()}")
    
    result.check(shared_alice == shared_bob, "DH with converted keys produces matching secrets")
    result.check(len(shared_alice) == 32, "DH with converted keys produces 32-byte secret")
    
    # Different Ed25519 keys produce different X25519 keys
    alice_ed2 = ed25519.Ed25519PrivateKey.generate()
    alice_x2 = NoiseCrypto.ed25519_to_x25519_private(alice_ed2)
    print(f"\n  Different Ed25519 -> X25519 public: {NoiseCrypto.x25519_public_bytes(alice_x2).hex()}")
    result.check(
        NoiseCrypto.x25519_public_bytes(alice_x) != NoiseCrypto.x25519_public_bytes(alice_x2),
        "Different Ed25519 keys produce different X25519 keys"
    )
    
    # ========================================================================
    # Summary
    # ========================================================================
    print()
    return result.summary()


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)