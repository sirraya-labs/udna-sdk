#!/usr/bin/env python3
"""
Comprehensive demo for Sirraya Labs UDNA SDK
After: pip install sirraya-udna-sdk

Walks through every public feature of UdnaSDK:
  1. DID creation (did:key and did:web)
  2. DID resolution
  3. UDNA address creation, verification, and tamper detection
  4. Key rotation
  5. Identity export / import / load
  6. Pairwise DIDs (privacy)
  7. Secure session establishment (Noise-style handshake) + encrypted messaging
  8. Storage-backed identities and listing

Run with: python demo.py
"""

import tempfile
from pathlib import Path

from udna_sdk import UdnaSDK


def section(title: str):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main():
    # ------------------------------------------------------------------
    # 1. DID creation
    # ------------------------------------------------------------------
    section("1. DID CREATION")

    sdk = UdnaSDK()

    key_did = sdk.create_did(method="key")
    print(f"did:key created:  {key_did.did}")

    web_did = sdk.create_did(method="web", domain="example.com")
    print(f"did:web created:  {web_did.did}")

    print(f"\nActive DIDs in this SDK instance: {len(sdk.list_active_dids())}")
    for did_str in sdk.list_active_dids():
        info = sdk.get_did_info(did_str)
        print(f"  - {info['did']} (method={info['method']}, has_key={info['has_private_key']})")

    # ------------------------------------------------------------------
    # 2. DID resolution
    # ------------------------------------------------------------------
    section("2. DID RESOLUTION")

    resolved = sdk.resolve_did(key_did.did)
    print(f"Resolved: {resolved['did']}")
    print(f"Verification methods: {[vm['type'] for vm in resolved['verification_methods']]}")
    print(f"Created: {resolved['created']}")

    # ------------------------------------------------------------------
    # 3. UDNA addresses: create, verify, tamper detection
    # ------------------------------------------------------------------
    section("3. UDNA ADDRESSES")

    address = sdk.create_address(key_did.did, facet_id=0x02, flags=["messaging", "routing"])
    print(f"Address:  {address.address}")
    print(f"Facet ID: 0x{address.facet_id:02x}")
    print(f"Flags:    {address.flags}")

    result = sdk.verify_address(address.address)
    print(f"\nVerification result: valid={result.is_valid}, did={result.did}")

    # Tampering should be detected
    tampered_address = address.address[:-4] + ("A" * 4)
    tampered_result = sdk.verify_address(tampered_address)
    print(f"Tampered address rejected: {not tampered_result.is_valid} "
          f"(error: {tampered_result.error[:60] if tampered_result.error else None}...)")

    # ------------------------------------------------------------------
    # 4. Key rotation
    # ------------------------------------------------------------------
    section("4. KEY ROTATION")

    rotation = sdk.rotate_keys(key_did.did, reason="regular_rotation")
    print(f"Rotation success: {rotation.success}")
    print(f"Old key fingerprint: {rotation.old_key_fingerprint}")
    print(f"New key fingerprint: {rotation.new_key_fingerprint}")
    print("(Addresses signed with the old key would need to be re-issued "
          "under the new key going forward.)")

    # ------------------------------------------------------------------
    # 5. Export / import / load identities
    # ------------------------------------------------------------------
    section("5. IDENTITY EXPORT / IMPORT / LOAD")

    with tempfile.TemporaryDirectory() as tmpdir:
        export_path = Path(tmpdir) / "identity.json"
        sdk.export_identity(key_did.did, str(export_path), format="json")
        print(f"Exported identity to: {export_path}")

        # A fresh SDK instance has no keys until you import or load one
        fresh_sdk = UdnaSDK()
        print(f"Fresh SDK active DIDs before import: {len(fresh_sdk.list_active_dids())}")

        imported = fresh_sdk.import_identity(str(export_path))
        print(f"Imported identity: {imported.did}")
        print(f"Fresh SDK active DIDs after import: {len(fresh_sdk.list_active_dids())}")

        # load_identity() is the same idea but takes a PEM string directly
        # rather than reading a file - useful if you're pulling the key
        # out of a secrets manager rather than local disk.
        pem = export_path.read_text()
        import json as _json
        pem_only = _json.loads(pem)["private_key_pem"]
        another_sdk = UdnaSDK()
        loaded_ok = another_sdk.load_identity(key_did.did, pem_only)
        print(f"load_identity() from PEM string succeeded: {loaded_ok}")

    # ------------------------------------------------------------------
    # 6. Pairwise DIDs (privacy)
    # ------------------------------------------------------------------
    section("6. PAIRWISE DIDS")

    alice_sdk = UdnaSDK()
    alice = alice_sdk.create_did()
    bob_sdk = UdnaSDK()
    bob = bob_sdk.create_did()

    alice_pairwise_with_bob = alice_sdk.create_pairwise_did(alice.did, bob.did)
    print(f"Alice's real DID:              {alice.did}")
    print(f"Alice's pairwise DID with Bob: {alice_pairwise_with_bob.did}")
    print("(This pairwise DID is unlinkable to Alice's real DID by anyone "
          "who only sees this relationship.)")

    # ------------------------------------------------------------------
    # 7. Secure sessions + encrypted messaging
    # ------------------------------------------------------------------
    section("7. SECURE SESSIONS & ENCRYPTED MESSAGING")

    # initiate_secure_session() -> alice sends init_msg to bob out-of-band
    session_alice, init_msg = alice_sdk.initiate_secure_session(alice.did, bob.did)
    print(f"Alice initiated session: {session_alice.session_id}")

    # respond_to_session() -> bob processes it and is immediately established
    session_bob, response_msg = bob_sdk.respond_to_session(bob.did, init_msg)
    print(f"Bob responded, session established on his side: "
          f"{session_bob.session_key_hash}")

    # complete_secure_session() -> alice processes bob's response
    session_alice_final = alice_sdk.complete_secure_session(session_alice.session_id, response_msg)
    print(f"Alice completed her side: {session_alice_final.session_key_hash}")
    print(f"Both sides agree on the session key: "
          f"{session_alice_final.session_key_hash == session_bob.session_key_hash}")

    plaintext = "Hello Bob, this message is end-to-end encrypted."
    ciphertext = alice_sdk.encrypt_message(session_alice.session_id, plaintext)
    print(f"\nAlice encrypted {len(plaintext)} chars -> {len(ciphertext)} bytes ciphertext")

    decrypted = bob_sdk.decrypt_message(session_bob.session_id, ciphertext)
    print(f"Bob decrypted: {decrypted!r}")
    print(f"Round trip successful: {decrypted == plaintext}")

    # ------------------------------------------------------------------
    # 8. Storage-backed identities
    # ------------------------------------------------------------------
    section("8. STORAGE-BACKED IDENTITIES")

    with tempfile.TemporaryDirectory() as storage_dir:
        storage_sdk = UdnaSDK(storage_dir=storage_dir)
        d1 = storage_sdk.create_did()
        d2 = storage_sdk.create_did()
        print(f"Created and persisted 2 identities under: {storage_dir}")

        listed = storage_sdk.list_identities()
        print(f"Identities on disk: {len(listed)}")
        for did_str in listed:
            print(f"  - {did_str}")

        # A brand new SDK instance pointed at the same storage_dir can see
        # the same identities on disk, even though it has no keys loaded
        # into memory yet.
        reopened_sdk = UdnaSDK(storage_dir=storage_dir)
        print(f"\nReopened SDK sees {len(reopened_sdk.list_identities())} "
              f"identities on disk, but {len(reopened_sdk.list_active_dids())} "
              f"loaded in memory (call import_identity() to load one).")

    section("DEMO COMPLETE")


if __name__ == "__main__":
    main()