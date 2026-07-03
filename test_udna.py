"""
Regression tests for the UDNA core module and SDK.

Covers the bugs fixed in v1.2.0 so they can't silently regress:
  - NoiseHandshake session key agreement (real X25519 DH, not public data)
  - DidDocument.get_public_key multicodec stripping
  - SDK respond_to_session / complete_secure_session wiring
  - Address create/verify round trip and tamper detection
  - Key rotation proof validity
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from udna import (
    Did,
    DidKeyMethod,
    UdnaAddress,
    NoiseHandshake,
    SecureMessaging,
    KeyRotationManager,
)
from udna_sdk import UdnaSDK


# ---------------------------------------------------------------------------
# DID basics
# ---------------------------------------------------------------------------

def test_did_key_generate_and_roundtrip_string():
    did, _ = DidKeyMethod.generate()
    assert str(did).startswith("did:key:z")
    assert Did.parse(str(did)) == did


def test_did_key_resolve_public_key_matches_generated_key():
    did, private_key = DidKeyMethod.generate()
    doc = DidKeyMethod.resolve(did)
    resolved_pub_bytes = doc.get_public_key(doc.authentication[0])

    expected_pub_bytes = private_key.public_key().public_bytes_raw()
    assert resolved_pub_bytes == expected_pub_bytes
    assert len(resolved_pub_bytes) == 32  # raw Ed25519 key, not multicodec-prefixed


# ---------------------------------------------------------------------------
# UDNA address encode/decode/sign/verify
# ---------------------------------------------------------------------------

def test_address_encode_decode_roundtrip():
    did, _ = DidKeyMethod.generate()
    addr = UdnaAddress(did=did, facet_id=0x02, nonce=12345, flags=3)
    decoded = UdnaAddress.decode(addr.encode())
    assert decoded.did == did
    assert decoded.facet_id == 0x02
    assert decoded.nonce == 12345
    assert decoded.flags == 3


def test_sdk_create_and_verify_address():
    sdk = UdnaSDK()
    did_info = sdk.create_did()
    address_info = sdk.create_address(did_info.did, flags=["messaging", "routing"])

    result = sdk.verify_address(address_info.address)
    assert result.is_valid
    assert result.did == did_info.did


def test_sdk_verify_address_rejects_tampering():
    sdk = UdnaSDK()
    did_info = sdk.create_did()
    address_info = sdk.create_address(did_info.did)

    tampered = address_info.address[:-4] + ("A" * 4)
    result = sdk.verify_address(tampered)
    assert not result.is_valid


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------

def test_key_rotation_proof_is_valid():
    did, old_key = DidKeyMethod.generate()
    new_key = ed25519.Ed25519PrivateKey.generate()

    manager = KeyRotationManager()
    proof = manager.rotate_key(did, old_key, new_key, reason=1)

    assert proof.verify(old_key.public_key())


def test_key_rotation_proof_rejects_wrong_key():
    did, old_key = DidKeyMethod.generate()
    new_key = ed25519.Ed25519PrivateKey.generate()
    wrong_key = ed25519.Ed25519PrivateKey.generate()

    manager = KeyRotationManager()
    proof = manager.rotate_key(did, old_key, new_key, reason=1)

    assert not proof.verify(wrong_key.public_key())


# ---------------------------------------------------------------------------
# Handshake / secure messaging (core module)
# ---------------------------------------------------------------------------

def test_handshake_both_sides_derive_same_session_key():
    alice_did, alice_key = DidKeyMethod.generate()
    bob_did, bob_key = DidKeyMethod.generate()

    handshake = NoiseHandshake()
    session_id, init_msg = handshake.initiate_handshake(alice_did, alice_key, bob_did)
    _, response_msg = handshake.respond_to_handshake(bob_did, bob_key, init_msg)
    alice_session_key = handshake.finalize_handshake(session_id, response_msg)

    bob_session_key = handshake.sessions[session_id]["session_key"]
    assert alice_session_key == bob_session_key
    assert len(alice_session_key) == 32


def test_handshake_rejects_wrong_recipient():
    alice_did, alice_key = DidKeyMethod.generate()
    bob_did, _ = DidKeyMethod.generate()
    eve_did, eve_key = DidKeyMethod.generate()

    handshake = NoiseHandshake()
    _, init_msg = handshake.initiate_handshake(alice_did, alice_key, bob_did)

    # Eve is not the intended recipient and should not be able to respond
    # to a handshake addressed to Bob.
    with pytest.raises(ValueError):
        handshake.respond_to_handshake(eve_did, eve_key, init_msg)


def test_encrypt_decrypt_roundtrip_with_derived_session_key():
    alice_did, alice_key = DidKeyMethod.generate()
    bob_did, bob_key = DidKeyMethod.generate()

    handshake = NoiseHandshake()
    session_id, init_msg = handshake.initiate_handshake(alice_did, alice_key, bob_did)
    _, response_msg = handshake.respond_to_handshake(bob_did, bob_key, init_msg)
    session_key = handshake.finalize_handshake(session_id, response_msg)

    messaging = SecureMessaging()
    ciphertext = messaging.encrypt_message(session_key, b"hello bob")
    assert messaging.decrypt_message(session_key, ciphertext) == b"hello bob"


# ---------------------------------------------------------------------------
# SDK-level session flow (respond_to_session / complete_secure_session)
# ---------------------------------------------------------------------------

def test_sdk_full_session_flow_and_message_roundtrip():
    alice = UdnaSDK()
    bob = UdnaSDK()
    a_id = alice.create_did()
    b_id = bob.create_did()

    session_a, init_msg = alice.initiate_secure_session(a_id.did, b_id.did)
    session_b, resp_msg = bob.respond_to_session(b_id.did, init_msg)
    session_a_final = alice.complete_secure_session(session_a.session_id, resp_msg)

    assert session_a_final.session_key_hash == session_b.session_key_hash

    ciphertext = alice.encrypt_message(session_a.session_id, "secret message")
    plaintext = bob.decrypt_message(session_b.session_id, ciphertext)
    assert plaintext == "secret message"


def test_encrypt_message_before_session_established_raises():
    sdk = UdnaSDK()
    with pytest.raises(ValueError):
        sdk.encrypt_message("nonexistent-session-id", "hi")


# ---------------------------------------------------------------------------
# resolve_did (asyncio event loop handling)
# ---------------------------------------------------------------------------

def test_resolve_did_returns_expected_shape():
    sdk = UdnaSDK()
    did_info = sdk.create_did()

    document = sdk.resolve_did(did_info.did)
    assert document["did"] == did_info.did
    assert len(document["verification_methods"]) == 1
