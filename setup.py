
from setuptools import setup, find_packages
from os import path

setup(
    name='knd-json-gateway',
    version='0.0.1',
    description='gateway to provide json-pure api',
    author='Globbie',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topics :: Database',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python :: 3.4',
    ],
    packages=['json_gateway'],
    install_requires=['pyzmq'],
    entry_points={
        'console_scripts': [
            'knd-json-gateway=json_gateway.__main__:main'
        ]
    },

)
