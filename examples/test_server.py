import logging
from asyncio import gather, get_event_loop, ensure_future

from colorlog import ColoredFormatter

from secret_handshake import SHSServer
from ssb.packet_stream import PacketStream
from ssb.protocol.streams import stream_api
from ssb.util import load_ssb_secret


async def on_connect(conn):
    packet_stream = PacketStream(conn)
    stream_api.add_connection(packet_stream)

    print('connect', conn)
    async for msg in packet_stream:
        print(msg)


async def main():
    server = SHSServer('127.0.0.1', 8008, load_ssb_secret()['keypair'])
    server.on_connect(on_connect)
    await server.listen()


if __name__ == '__main__':
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
    loop.run_until_complete(main())
    loop.run_forever()
    loop.close()
