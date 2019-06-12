import os
import yaml
from base64 import b64decode, b64encode

from nacl.signing import SigningKey


class ConfigException(Exception):
    pass


def tag(key):
    """Create tag from publick key."""
    return b'@' + b64encode(bytes(key)) + b'.ed25519'


def load_ssb_secret():
    """Load SSB keys from ~/.ssb"""
    with open(os.path.expanduser('~/.ssb/secret')) as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)

    if config['curve'] != 'ed25519':
        raise ConfigException('Algorithm not known: ' + config['curve'])

    server_prv_key = b64decode(config['private'][:-8])
    return {
        'keypair': SigningKey(server_prv_key[:32]),
        'id': config['id']
    }
