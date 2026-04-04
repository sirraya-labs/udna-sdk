"""
Sirraya Labs UDNA SDK
W3C Universal DID-Native Addressing Implementation

A production-ready SDK for Decentralized Identifiers (DIDs) and
UDNA addresses, compliant with W3C standards.

Copyright (c) 2026 Sirraya Labs
License: MIT
"""

from .core import UdnaSDK, UdnaAddressInfo, DidInfo, VerificationResult
from .udna import AddressFlags
from .version import __version__

__author__ = "Sirraya Labs"
__copyright__ = "Copyright (c) 2026 Sirraya Labs"
__license__ = "MIT"
__version__ = "1.0.0"
__credits__ = ["Based on W3C Universal DID-Native Addressing specification"]