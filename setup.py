#
# Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
#
# NOTICE:  All information contained herein is, and remains the property
# of Ubiq Security, Inc. The intellectual and technical concepts contained
# herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
# covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law. Dissemination of this
# information or reproduction of this material is strictly forbidden
# unless prior written permission is obtained from Ubiq Security, Inc.
#
# Your use of the software is expressly conditioned upon the terms
# and conditions available at:
#
#     https://ubiqsecurity.com/legal
#

import os
import setuptools

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

os.chdir(here)


with open(os.path.join(here, "README.md"), "r", encoding="utf-8") as f:
    long_description = f.read()

version_contents = {}
with open(os.path.join(here, "ubiq_security", "version.py"), "r", encoding="utf-8") as f:
    exec(f.read(), version_contents)

requirementPath = os.path.join(here, "requirements.txt")
install_requires = [] 
if os.path.isfile(requirementPath):
    with open(requirementPath, "r", encoding="utf-8") as f:
        install_requires = f.read().splitlines()

setuptools.setup(
    name="ubiq-security",
    version=version_contents["VERSION"],
    author="Ubiq Security, Inc.",
    author_email="support@ubiqsecurity.com",
    description="Python client library for accessing Ubiq Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/ubiqsecurity/ubiq-python",
    packages=setuptools.find_packages(),
    install_requires=install_requires,
    license="Free To Use But Restricted",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: Free To Use But Restricted",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
        "Topic :: Security :: Cryptography"
    ],
    python_requires='>=3.5',
)

