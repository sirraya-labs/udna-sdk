from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    # Package name (PyPI)
    name="sirraya-udna-sdk",
    version="1.0.4",
    
    # Author information
    author="Sirraya Labs",
    author_email="amir@sirraya.org",
    
    # Description
    description="Sirraya Labs UDNA SDK - W3C Universal DID-Native Addressing Implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    
    # URLs
    url="https://github.com/sirraya-labs/udna-sdk",
    project_urls={
        "Documentation": "https://docs.sirraya.org/udna-sdk",
        "Source": "https://github.com/sirraya-labs/udna-sdk",
        "Tracker": "https://github.com/sirraya-labs/udna-sdk/issues",
        "W3C Specification": "https://w3c.github.io/did-core/",
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
    
    # Additional classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
        "Topic :: Internet :: WWW/HTTP",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    
    # Keywords for PyPI search
    keywords="did, udna, decentralized-identifier, w3c, sirraya, blockchain, identity, ssi",
    
    # CLI entry point
    entry_points={
        "console_scripts": [
            "sirraya-udna=sirraya_udna.cli:main",
            "udna=sirraya_udna.cli:main",  # Alias for convenience
        ],
    },
    
    # Include package data
    include_package_data=True,
    zip_safe=False,
)