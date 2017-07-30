import logging
import os
import struct
import time
from asyncio import get_event_loop, gather, ensure_future
from base64 import b64decode

import yaml
from colorlog import ColoredFormatter
from nacl.signing import SigningKey

from ssb.muxrpc import MuxRPCAPI, MuxRPCAPIException
from ssb.packet_stream import PSClient, PSMessageType


with open(os.path.expanduser('~/.ssb/secret')) as f:
    config = yaml.load(f)


api = MuxRPCAPI()


@api.define('createHistoryStream')
def create_history_stream(connection, msg):
    print('create_history_stream', msg)
    # msg = PSMessage(PSMessageType.JSON, True, stream=True, end_err=True, req=-req)
    # connection.write(msg)


@api.define('blobs.createWants')
def create_wants(connection, msg):
    print('create_wants', msg)


async def main():
    async for msg in api.call('createHistoryStream', [{
        'id': "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519",
        'seq': 1,
        'live': False,
        'keys': False
    }], 'source'):
        print('> RESPONSE:', msg)

    try:
        print('> RESPONSE:', await api.call('whoami', [], 'sync'))
    except MuxRPCAPIException as e:
        print(e)

    handler = api.call('gossip.ping', [], 'duplex')
    handler.send(struct.pack('l', int(time.time() * 1000)), msg_type=PSMessageType.BUFFER)
    async for msg in handler:
        print('> RESPONSE:', msg)
        handler.send(True, end=True)
        break

    async for data in api.call('blobs.get', ['&/6q7JOKythgnnzoBI5xxvotCr5HeFkAIZSAuqHiZfLw=.sha256'], 'source'):
        if data.type.name == 'BUFFER':
            with open('./funny_img.png', 'wb') as f:
                f.write(data.data)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# create formatter
formatter = ColoredFormatter('%(log_color)s%(levelname)s%(reset)s:%(bold_white)s%(name)s%(reset)s - '
                             '%(cyan)s%(message)s%(reset)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger = logging.getLogger('packet_stream')
logger.setLevel(logging.DEBUG)
logger.addHandler(ch)

server_pub_key = b64decode(config['public'][:-8])
# server_prv_key = b64decode(config['private'][:-8])
# sign = SigningKey(server_prv_key[:32])

loop = get_event_loop()
packet_stream = PSClient('127.0.0.1', 8008, SigningKey.generate(), server_pub_key, loop=loop)
packet_stream.connect()
api.add_connection(packet_stream)

loop.run_until_complete(gather(ensure_future(api), main()))
loop.close()
