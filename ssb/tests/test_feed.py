from base64 import b64decode
from collections import OrderedDict

import pytest
from nacl.signing import SigningKey

from ssb.feed import LocalMessage, LocalFeed


@pytest.fixture()
def feed():
    secret = b64decode('Mz2qkNOP2K6upnqibWrR+z8pVUI1ReA1MLc7QMtF2qQ=')
    return LocalFeed(SigningKey(secret))


def test_feed():
    secret = b64decode('Mz2qkNOP2K6upnqibWrR+z8pVUI1ReA1MLc7QMtF2qQ=')
    feed = LocalFeed(SigningKey(secret))
    assert bytes(feed.private_key) == secret
    assert bytes(feed.public_key) == b64decode('I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=')
    assert feed.id == '@I/4cyN/jPBbDsikbHzAEvmaYlaJK33lW3UhWjNXjyrU=.ed25519'


def test_message(feed):
    m1 = LocalMessage(feed, OrderedDict([
        ('type', 'about'),
        ('about', feed.id),
        ('name', 'neo'),
        ('description', 'The Chosen One')
    ]), timestamp=1495706260190)
    assert m1.timestamp == 1495706260190
    assert m1.previous is None
    assert m1.sequence == 1
    assert m1.signature == \
        'lPsQ9P10OgeyH6u0unFgiI2wV/RQ7Q2x2ebxnXYCzsJ055TBMXphRADTKhOMS2EkUxXQ9k3amj5fnWPudGxwBQ==.sig.ed25519'
    assert m1.key == '%xRDqws/TrQmOd4aEwZ32jdLhP873ZKjIgHlggPR0eoo=.sha256'

    m2 = LocalMessage(feed, OrderedDict([
        ('type', 'about'),
        ('about', feed.id),
        ('name', 'morpheus'),
        ('description', 'Dude with big jaw')
    ]), previous=m1, timestamp=1495706447426)
    assert m2.timestamp == 1495706447426
    assert m2.previous is m1
    assert m2.sequence == 2
    assert m2.signature == \
        '3SY85LX6/ppOfP4SbfwZbKfd6DccbLRiB13pwpzbSK0nU52OEJxOqcJ2Uensr6RkrWztWLIq90sNOn1zRAoOAw==.sig.ed25519'
    assert m2.key == '%nx13uks5GUwuKJC49PfYGMS/1pgGTtwwdWT7kbVaroM=.sha256'
