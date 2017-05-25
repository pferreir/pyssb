import hashlib

import pytest
from nacl.public import PrivateKey

from ssb.shs import SecretHandShake


@pytest.fixture()
def appkey():
    return hashlib.sha256(b'app_key').digest()


def test_client_challenge(appkey):
    pk = PrivateKey.generate()
    shs = SecretHandShake(pk, application_key=appkey)
    assert shs.client_challenge
