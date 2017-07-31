import logging
import os
from asyncio import get_event_loop, ensure_future
from base64 import b64decode

import yaml
from colorlog import ColoredFormatter
from nacl.signing import SigningKey

from ssb.packet_stream import PSServer


with open(os.path.expanduser('~/.ssb/secret')) as f:
    config = yaml.load(f)


async def on_connect():
    loop.create_task(ensure_future(packet_stream))

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = ColoredFormatter('%(log_color)s%(levelname)s%(reset)s:%(bold_white)s%(name)s%(reset)s - '
                             '%(cyan)s%(message)s%(reset)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger = logging.getLogger('packet_stream')
logger.setLevel(logging.DEBUG)
logger.addHandler(ch)


loop = get_event_loop()

server_keypair = SigningKey(b64decode(config['private'][:-8])[:32])
packet_stream = PSServer('127.0.0.1', 8008, server_keypair, loop=loop)
packet_stream.on_connect(on_connect)
packet_stream.listen()

loop.run_forever()
loop.close()
