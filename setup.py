"""setup.py

Package setup.
"""


# pylint: disable=invalid-name

# import os

from setuptools import find_packages
from setuptools import setup


install_requires=[
    'boto3>=1.7.25',
    'click>=6.7',
    'pycryptodome>=3.6.4',
    ],

package_data={
    '': [
        ]
    },

# # Construct a list of all scripts to be installed.
# script_files = os.listdir(
#     os.path.join(
#         os.path.dirname(os.path.realpath(__file__)),
#         'bin'
#         )
#     )

# scripts reside in bin dirs.
script_package_paths = [
    # Uncomment to enable.
    # os.path.join('bin', s) for s in script_files
    ]

entry_points={
    'console_scripts': [
        'ckcreate = cryptkeeper.envelope:create_envelope',
        'ckopen = cryptkeeper.envelope:open_envelope',
        ],
    }

setup(
    name="cryptkeeper",
    version="1.0.1",
    description="",
    author="Scott Brown",
    author_email='scottbrown0001@gmail.com',
    url="https:////",
    packages=find_packages(exclude=['test_*']),
    # package_data=package_data,
    # scripts=script_package_paths,
    install_requires=install_requires,
    entry_points=entry_points,
    )
