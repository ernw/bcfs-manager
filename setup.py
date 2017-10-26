#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name='bcfs_manager',
    version='0.0.1',
    description='Interact with the bluecoat file system',
    url='https://github.com/ernw/bcfs-manager',
    license='GPLv3',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: X11 Applications :: Qt',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Topic :: System :: Filesystems'
    ],
    keywords='bluecoat filesystem sgos',
    packages=[
        'bluecoat_tools',
        'bluecoat_tools.config',
        'bluecoat_tools.filesystem',
        'bluecoat_tools.gui'
    ],
    package_data={
        '': ['*.json', '*.pem', '*.key']
    },
    install_requires=open('requirements.txt').read(),
    entry_points={
        'gui_scripts': [
            'bcfs-manager = bluecoat_tools.gui:main'
        ]
    }
)
