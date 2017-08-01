**WORK IN PROGRESS**

pyssb - Secure Scuttlebutt in Python
====================================

|build-status| |code-coverage|

Please, don't use this for anything that is not experimental. This is a first attempt at implementing the main
functionality needed to run an SSB client/server.

Things that are currently implemented:

 * Basic Message feed logic
 * Secret Handshake
 * packet-stream protocol

Usage::

    $ pip install -r requirements.txt

Check the ``test_*.py`` files for basic examples.

.. |build-status| image:: https://travis-ci.org/pferreir/pyssb.svg?branch=master
                   :alt: Travis Build Status
                   :target: https://travis-ci.org/pferreir/pyssb
.. |code-coverage| image:: https://coveralls.io/repos/github/pferreir/pyssb/badge.svg?branch=master
                   :alt: Code Coverage
                   :target: https://coveralls.io/github/pferreir/pyssb?branch=master
