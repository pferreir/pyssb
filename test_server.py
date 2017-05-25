from asyncio import get_event_loop
from base64 import b64decode

from ssb.keys import KeyPair
from ssb.packet_stream import PSServer


priv_key = b64decode('--- your private key ---')


async def main(loop):
    await packet_stream.listen(loop)


async def on_connect(server):
    await server.write('JSON', {"name": ["createHistoryStream"],
                                "args": [{
                                    "id": "@/Odg52x38pt7OivNnxK1Lm+H/+x6yV4DhMeXHBQRYc0=.ed25519",
                                    "seq": 9,
                                    "live": True,
                                    "keys": False
                                }],
                                "type": "source"}, req=1)
    print(await server.read().__anext__())

packet_stream = PSServer('127.0.0.1', 8008, KeyPair(priv_key[:32]))
packet_stream.on_connect(on_connect)
loop = get_event_loop()
loop.run_until_complete(main(loop))
loop.run_forever()
loop.close()
