from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    # Package name (PyPI)
    name="sirraya-udna-sdk",
    version="1.1.1",

    # Author (Copyright Holder)
    author="Amir Hameed Mir",
    author_email="amir@sirraya.org",

    # Maintainer
    maintainer="Sirraya Labs",
    maintainer_email="amir@sirraya.org",

    # License
    license="Business Source License 1.1",
    license_files=("LICENSE",),

    # Description
    description="Universal DID-Native Addressing (UDNA) SDK by Sirraya Labs",
    long_description=long_description,
    long_description_content_type="text/markdown",

    # Project URLs
    url="https://github.com/sirraya-labs/udna-sdk",
    project_urls={
        "Documentation": "https://docs.sirraya.org/udna-sdk",
        "Source": "https://github.com/sirraya-labs/udna-sdk",
        "Issue Tracker": "https://github.com/sirraya-labs/udna-sdk/issues",
        "W3C DID Core": "https://w3c.github.io/did-core/",
    },

    # Package discovery
    packages=find_packages(exclude=["tests", "docs"]),

    # Python version requirement
    python_requires=">=3.7",

    # Dependencies
    install_requires=[
        "cryptography>=41.0.0",
        "base58>=2.1.0",
    ],

    # PyPI Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
        "Topic :: Internet",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],

    # Search keywords
    keywords=[
        "udna",
        "did",
        "decentralized identity",
        "w3c",
        "ssi",
        "cryptography",
        "identity",
        "routing",
        "pairwise did",
        "sirraya",
    ],

    # Command-line interface
    entry_points={
        "console_scripts": [
            "sirraya-udna=sirraya_udna.cli:main",
            "udna=sirraya_udna.cli:main",
        ],
    },

    # Include package data
    include_package_data=True,
    zip_safe=False,
)