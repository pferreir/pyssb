import os
from asyncio import get_event_loop
from base64 import b64decode

import yaml
from nacl.signing import SigningKey

from ssb.packet_stream import PSClient


with open(os.path.expanduser('~/.ssb/secret')) as f:
    config = yaml.load(f)


server_pub_key = b64decode(config['public'][:-8])


async def main(loop):
    async for msg in packet_stream:
        print(msg)
    print('bye')

loop = get_event_loop()

packet_stream = PSClient('127.0.0.1', 8008, SigningKey.generate(), server_pub_key, loop=loop)
packet_stream.connect()
loop.run_until_complete(main(loop))
loop.close()
