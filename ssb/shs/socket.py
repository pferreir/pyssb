from asyncio import open_connection, start_server

from ..boxstream import get_stream_pair
from .crypto import SHSClientCrypto, SHSServerCrypto


class SHSClientException(Exception):
    pass


class SHSSocket(object):
    async def read(self):
        async for msg in self.read_stream.process():
            yield msg

    async def write(self, data):
        await self.write_stream.write(data)

    async def disconnect(self):
        self.writer.close()


class SHSServer(SHSSocket):
    def __init__(self, host, port, server_kp, application_key=None):
        self.host = host
        self.port = port
        self.crypto = SHSServerCrypto(server_kp.private_key, application_key=application_key)
        self._on_connect = None

    async def _handshake(self, reader, writer):
        data = await reader.read(64)
        if not self.crypto.verify_challenge(data):
            raise SHSClientException('Client challenge is not valid')

        writer.write(self.crypto.generate_challenge())

        data = await reader.read(112)
        if not self.crypto.verify_client_auth(data):
            raise SHSClientException('Client auth is not valid')

        writer.write(self.crypto.generate_accept())

    async def handle_connection(self, reader, writer):
        self.crypto.clean()
        await self._handshake(reader, writer)

        keys = self.crypto.get_box_keys()
        self.crypto.clean()

        self.read_stream, self.write_stream = get_stream_pair(reader, writer, **keys)
        self.writer = writer

        if self._on_connect:
            await self._on_connect()

    async def listen(self, loop=None):
        await start_server(self.handle_connection, self.host, self.port, loop=loop)


class SHSClient(SHSSocket):
    def __init__(self, host, port, client_kp, server_pub_key, ephemeral_key=None, application_key=None):
        self.host = host
        self.port = port
        self.crypto = SHSClientCrypto(client_kp.private_key, server_pub_key, ephemeral_key=ephemeral_key,
                                      application_key=application_key)

    async def _handshake(self, reader, writer):
        writer.write(self.crypto.generate_challenge())

        data = await reader.read(64)
        if not self.crypto.verify_server_challenge(data):
            raise SHSClientException('Server challenge is not valid')

        writer.write(self.crypto.generate_client_auth())

        data = await reader.read(80)
        if not self.crypto.verify_server_accept(data):
            raise SHSClientException('Server accept is not valid')

    async def connect(self, loop=None):
        reader, writer = await open_connection(self.host, self.port, loop=loop)
        await self._handshake(reader, writer)

        keys = self.crypto.get_box_keys()
        self.crypto.clean()

        self.read_stream, self.write_stream = get_stream_pair(reader, writer, **keys)
        self.writer = writer
