#!/usr/bin/env python3
# setup.py — JagoX packaging (legacy, kompatibel pip lama)
# MIT License
# Untuk packaging modern, lihat pyproject.toml

import os
from setuptools import setup, find_packages

BASE = os.path.dirname(os.path.abspath(__file__))
readme_path = os.path.join(BASE, "README.md")
long_desc = "JagoX — Automatic Security Scanner Framework"
if os.path.exists(readme_path):
    with open(readme_path, "r", encoding="utf-8") as f:
        long_desc = f.read()

setup(
    name="jagox",
    version="1.0.0",
    description="JagoX — Automatic Nmap + Web Vulnerability Scanner Framework",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    author="JagoX Project",
    license="MIT",
    url="https://github.com/USERNAME/JagoX",
    python_requires=">=3.8",
    py_modules=["jagox", "nmpx"],
    packages=find_packages(include=["modules", "modules.*"]),
    include_package_data=True,
    package_data={
        "modules": ["plugins/*.py"],
    },
    install_requires=[
        "rich>=12.0.0",
    ],
    extras_require={
        "tui": ["prompt_toolkit>=3.0.0"],
        "osint": ["python-whois", "geoip2"],
        "full": ["prompt_toolkit>=3.0.0", "python-whois", "geoip2"],
    },
    entry_points={
        "console_scripts": [
            "jagox=jagox:main",
            "nmpx=nmpx:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="security scanner nmap pentest sql-injection xss osint tls",
)
