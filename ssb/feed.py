import time
from base64 import b64encode
from collections import namedtuple, OrderedDict
from hashlib import sha256

from simplejson import dumps, loads


OrderedMsg = namedtuple('OrderedMsg', ('previous', 'author', 'sequence', 'timestamp', 'hash', 'content'))


def to_ordered(data):
    smsg = OrderedMsg(**data)
    return OrderedDict((k, getattr(smsg, k)) for k in smsg._fields)


class Message(object):
    def __init__(self, keypair, content, timestamp=None, previous=None):
        self.keypair = keypair
        self.content = content
        self.previous = previous
        self.sequence = (self.previous.sequence + 1) if self.previous else 1
        self.timestamp = int(time.time() * 1000) if timestamp is None else timestamp

    @classmethod
    def parse(cls, data, keypair):
        obj = loads(data, object_pairs_hook=OrderedDict)
        msg = cls(keypair, obj['content'], timestamp=obj['timestamp'])
        return msg, obj['signature']

    def to_dict(self, add_signature=True):
        obj = to_ordered({
            'previous': self.previous.key if self.previous else None,
            'author': self.keypair.tag,
            'sequence': self.sequence,
            'timestamp': self.timestamp,
            'hash': 'sha256',
            'content': self.content
        })

        if add_signature:
            obj['signature'] = self.signature
        return obj

    @property
    def signature(self):
        # ensure ordering of keys and indentation of 2 characters, like ssb-keys
        data = dumps(self.to_dict(add_signature=False), indent=2)
        return (b64encode(bytes(self.keypair.sign(data.encode('ascii')))) + b'.sig.ed25519').decode('ascii')

    def verify(self, signature):
        return self.signature == signature

    @property
    def hash(self):
        hash = sha256(dumps(self.to_dict(), indent=2).encode('ascii')).digest()
        return b64encode(hash).decode('ascii') + '.sha256'

    @property
    def key(self):
        return '%' + self.hash
