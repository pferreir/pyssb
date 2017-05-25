from asyncio import get_event_loop
from base64 import b64decode

from ssb.keys import KeyPair
from ssb.packet_stream import PSClient

server_pub_key = b64decode('--- your public key ---')


async def main(loop):
    await packet_stream.connect(loop)
    async for msg in packet_stream.read():
        print(msg)
    print('bye')

packet_stream = PSClient('127.0.0.1', 8008, KeyPair(), server_pub_key)
loop = get_event_loop()
loop.run_until_complete(main(loop))
loop.close()
