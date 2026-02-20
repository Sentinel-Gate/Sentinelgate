"""Setup script for the SentinelGate Python SDK."""

from setuptools import setup, find_packages

setup(
    name="sentinelgate",
    version="0.1.0",
    description="Python SDK for SentinelGate Policy Decision API",
    long_description="Thin client wrapper around the SentinelGate Policy Decision API. "
    "Evaluate agent actions against policies with allow/deny/approval_required decisions.",
    author="SentinelGate",
    url="https://github.com/Sentinel-Gate/Sentinelgate",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.8",
    install_requires=[],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
