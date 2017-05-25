import struct
from nacl.secret import SecretBox

from .util import bytes_to_long, long_to_bytes

NONCE_SIZE = 24
HEADER_LENGTH = 2 + 16 + 16
MAX_SEGMENT_SIZE = 4 * 1024
TERMINATION_HEADER = (b'\x00' * HEADER_LENGTH)
MAX_NONCE = (8 * NONCE_SIZE)


def inc_nonce(nonce):
    num = bytes_to_long(nonce) + 1
    if num > 2**MAX_NONCE:
        num = 0
    bnum = long_to_bytes(num)
    bnum = b'\x00' * (NONCE_SIZE - len(bnum)) + bnum
    return bnum


def get_stream_pair(reader, writer, **kwargs):
    shared_secret = kwargs.pop('shared_secret')
    return UnboxStream(reader, shared_secret, **kwargs), BoxStream(writer, shared_secret, **kwargs)


class UnboxStream(object):
    def __init__(self, reader, shared_secret, **key_data):
        self.reader = reader
        self.decrypt_key = key_data.get('decrypt_key')
        self.decrypt_nonce = key_data.get('decrypt_nonce')

    async def process(self):
        while True:
            data = await self.reader.read(HEADER_LENGTH)
            if not data:
                break

            box = SecretBox(self.decrypt_key)
            header = box.decrypt(data, self.decrypt_nonce)

            if header == TERMINATION_HEADER:
                return

            length = struct.unpack('>H', header[:2])[0]
            mac = header[2:]

            data = await self.reader.read(length)

            self.decrypt_nonce = inc_nonce(self.decrypt_nonce)
            body = box.decrypt(mac + data, self.decrypt_nonce)

            self.decrypt_nonce = inc_nonce(self.decrypt_nonce)
            yield body
        print('Disconnect')


class BoxStream(object):
    def __init__(self, writer, shared_secret, **key_data):
        self.writer = writer
        self.encrypt_key = key_data.get('decrypt_key')
        self.encrypt_nonce = key_data.get('decrypt_nonce')

    async def write(self, data):
        box = SecretBox(self.encrypt_key)

        # XXX: This nonce logic is almost for sure wrong

        self.encrypt_nonce = inc_nonce(self.encrypt_nonce)

        body = box.encrypt(data, self.encrypt_nonce)
        header = struct.pack('>H', len(body)) + body[:16]

        self.writer.write(box.encrypt(header, self.encrypt_nonce))

        self.encrypt_nonce = inc_nonce(self.encrypt_nonce)
        self.writer.write(body)
