import logging
from asyncio import get_event_loop, ensure_future

from colorlog import ColoredFormatter

from ssb.packet_stream import PSServer
from ssb.util import load_ssb_secret


async def on_connect():
    ensure_future(packet_stream, loop=loop)

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

packet_stream = PSServer('127.0.0.1', 8008, load_ssb_secret()['keypair'], loop=loop)
packet_stream.on_connect(on_connect)
packet_stream.listen()

loop.run_forever()
loop.close()
