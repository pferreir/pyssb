# Copyright (c) 2017 PySecretHandshake contributors (see AUTHORS for more details)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""A module that implements Secret Handshake as specified in "Designing a Secret Handshake: Authenticated
Key Exchange as a Capability System" (Dominic Tarr, 2015)."""

from setuptools import find_packages, setup

readme = open('README.rst').read()
history = open('CHANGES.rst').read()

tests_require = [
    'check-manifest>=0.39',
    'coverage>=4.5.3',
    'isort>=4.3.20',
    'pep257>=0.7.0',
    'pytest-cov>=2.7.1',
    'pytest>=4.6.3',
    'pytest-asyncio==0.10.0',
    'asynctest==0.13.0',
    'pytest-mock==1.10.4'
]

extras_require = {
    'docs': [
        'Sphinx>=2.1.1',
    ],
    'tests': tests_require,
}
extras_require['all'] = sum((lst for lst in extras_require.values()), [])

install_requires = [
    'async-generator==1.10',
    'pynacl==1.3.0',
    'pyyaml>=4.2b1',
    'secret-handshake',
    'simplejson==3.16.0'
]

setup_requires = [
    'pytest-runner'
]

packages = find_packages()

setup(
    name='ssb',
    version='0.1.0.dev3',
    description=__doc__,
    long_description=(readme + '\n\n' + history),
    license='MIT',
    author='PyScuttleButt Contributors',
    author_email='pedro@dete.st',
    url='https://github.com/pferreir/PyScuttlebutt',
    packages=packages,
    include_package_data=True,
    extras_require=extras_require,
    install_requires=install_requires,
    setup_requires=setup_requires,
    tests_require=tests_require,
    zip_safe=False,
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6'
    ],
)
