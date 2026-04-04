#!/usr/bin/env python3
"""
Demo for Sirraya Labs UDNA SDK
After: pip install sirraya-udna-sdk
"""

from udna_sdk import UdnaSDK


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