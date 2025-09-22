"""
Setup script for ICS Security Sentinel

Industrial Control Systems Security Monitoring Framework
Author: Marco Lucchese
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Read requirements
requirements = []
with open('requirements.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('-'):
            requirements.append(line)

setup(
    name="ics-security-sentinel",
    version="1.0.0",
    author="Marco Lucchese",
    author_email="marco.lucchese@gmx.com",
    description="Industrial Control Systems Security Monitoring and Threat Detection Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/marcolucchese/ics-security-sentinel",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0", 
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.4.0",
            "pre-commit>=3.3.0"
        ],
        "ml": [
            "tensorflow>=2.13.0",
            "torch>=2.0.0"
        ],
        "cloud": [
            "boto3>=1.28.0",
            "azure-identity>=1.13.0", 
            "google-cloud-logging>=3.5.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "ics-sentinel=ics_security_sentinel.cli:main",
            "ics-monitor=ics_security_sentinel.scripts.monitor:main",
            "ics-report=ics_security_sentinel.scripts.report:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ics_security_sentinel": [
            "config/*.yaml",
            "config/sigma_rules/*.yml", 
            "templates/*.html",
            "static/*"
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/marcolucc/ics-sentinel/issues",
        "Source": "https://github.com/marcolucc/ics-sentinel",
        "Documentation": "https://github.com/marcolucc/ics-sentinel/wiki",
    },
)
