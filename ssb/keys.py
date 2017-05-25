from base64 import b64encode

from nacl.signing import SigningKey


def tag(key):
    """Create tag from publick key."""
    return b'@' + b64encode(bytes(key)) + b'.ed25519'


class KeyPair(object):
    def __init__(self, seed=None):
        self.private_key = SigningKey.generate() if seed is None else SigningKey(seed)
        self.public_key = self.private_key.verify_key

    @property
    def tag(self):
        return tag(self.public_key).decode('ascii')

    @property
    def private_tag(self):
        return tag(self.private_key)

    def sign(self, data):
        return self.private_key.sign(data).signature

    def __repr__(self):
        return "<KeyPair {0.tag}>".format(self)
