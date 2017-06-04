import os
from asyncio import get_event_loop
from base64 import b64decode

import yaml
from nacl.signing import SigningKey

from ssb.packet_stream import PSServer


with open(os.path.expanduser('~/.ssb/secret')) as f:
    config = yaml.load(f)


async def on_connect(server):
    server.write('JSON', {
        "name": ["createHistoryStream"],
        "args": [{
            "id": "@/Odg52x38pt7OivNnxK1Lm+H/+x6yV4DhMeXHBQRYc0=.ed25519",
            "seq": 9,
            "live": True,
            "keys": False
        }],
        "type": "source"}, req=1)
    print(await server.read())
    server.write('JSON', {})

loop = get_event_loop()

server_keypair = SigningKey(b64decode(config['private'][:-8])[:32])
packet_stream = PSServer('127.0.0.1', 8008, server_keypair, loop=loop)
packet_stream.on_connect(on_connect)
packet_stream.listen()

loop.run_forever()
loop.close()
