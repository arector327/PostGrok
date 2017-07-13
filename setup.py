#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


requirements = [
    "vivisect",
    "xlsxwriter",
    "six"
]

setup(
    name='postgrok',
    version='1.0.0',
    description="",
    long_description="",
    author="Andrew Rector",
    author_email='andrew.rector@mandiant.com',
    url='https://github.com/arector327/PostGrok',
    packages=[
        'postgrok'
    ],
    entry_points={
        "console_scripts": [
            "postgrok=postgrok.main:main",
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    zip_safe=False,
    keywords='postgrok',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Security',
        'Intended Audience :: Developers',
        'Topic :: System :: Recovery Tools',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
    ],
)
