#!/usr/bin/env python3
"""
Demo for Sirraya Labs UDNA SDK
After: pip install sirraya-udna-sdk
"""

from udna_sdk import UdnaSDK

print("=" * 60)
print("Sirraya Labs UDNA SDK Demo")
print("=" * 60)

# Initialize SDK
sdk = UdnaSDK()

private_key_export = sdk.export_private_key(did.did, format="pem")

# Create a DID
print("\n[1] Creating DID...")
did = sdk.create_did()
print(f"    DID: {did.did}")
print(f"    Method: {did.method}")

# Create a UDNA address
print("\n[2] Creating UDNA address...")
address = sdk.create_address(
    did.did,
    facet_id=0x02,
    flags=["messaging", "routing"]
)
print(f"    Address: {address.address[:60]}...")
print(f"    Flags: {', '.join(address.flags)}")
print(f"    Facet ID: 0x{address.facet_id:02x}")

# Verify the address
print("\n[3] Verifying address...")
result = sdk.verify_address(address.address)
print(f"    Valid: {result.is_valid}")

print("\n" + "=" * 60)
print("✅ UDNA SDK is working correctly!")
print("=" * 60)