#!/usr/bin/env python3
"""
Setup script for Overlay-CyberTech Unified Security Platform
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding='utf-8') if readme_file.exists() else ""

setup(
    name="overlay-cybertech",
    version="1.0.0",
    author="Overlay Eco",
    author_email="ncsound919@gmail.com",
    description="Advanced Cyber Security Software with Cross-Platform Support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ncsound919/Overlay-CyberTech-",
    packages=find_packages(exclude=['tests', 'tests.*']),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Core dependencies - minimal footprint for deterministic security
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0",
        "mypy>=1.0.0",
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'mypy>=1.0.0',
            'black>=22.0.0',
            'flake8>=4.0.0',
            'isort>=5.10.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'overlay-cybertech=main:main',
            'oct=main:main',  # Short alias
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        'cybersecurity', 'security', 'threat-detection', 'intrusion-detection',
        'system-cleaning', 'antivirus', 'malware-detection', 'cross-platform',
        'windows', 'linux', 'macos', 'formal-verification'
    ],
    project_urls={
        'Bug Reports': 'https://github.com/ncsound919/Overlay-CyberTech-/issues',
        'Source': 'https://github.com/ncsound919/Overlay-CyberTech-',
    },
)
