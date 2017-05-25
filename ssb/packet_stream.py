import struct
from enum import Enum

from .shs.socket import SHSClient, SHSServer

import simplejson


class PSMessageType(Enum):
    BUFFER = 0
    TEXT = 1
    JSON = 2


class PSMessage(object):
    def __init__(self, stream, end_err, type_, body):
        self.stream = stream
        self.end_err = end_err
        self.type = PSMessageType(type_)
        self.body = body

    @property
    def data(self):
        if self.type == PSMessageType.TEXT:
            return self.body.decode('utf-8')
        elif self.type == PSMessageType.JSON:
            return simplejson.loads(self.body)
        return self.body

    def __repr__(self):
        return '<PSMessage ({}): {}>'.format(self.type.name, self.data)


class PSSocket(object):
    async def read(self):
        while True:
            try:
                header = await self.connection.read().__anext__()
                body = await self.connection.read().__anext__()
                flags, length, req = struct.unpack('>BIi', header)
                yield PSMessage(bool(flags & 0x08), bool(flags & 0x04), flags & 0x03, body)
            except StopAsyncIteration:
                await self.connection.disconnect()
                break

    async def write(self, type_, data, req=0):
        type_ = PSMessageType[type_]
        if type_ == PSMessageType.JSON:
            data = simplejson.dumps(data)

        # XXX: Not yet handling flags that nicely

        header = struct.pack('>BIi', 0x08 | type_.value, len(data), req)
        await self.connection.write(header)
        await self.connection.write(data.encode('utf-8'))


class PSClient(PSSocket):
    def __init__(self, host, port, client_kp, server_pub_key, ephemeral_key=None, application_key=None):
        self.connection = SHSClient(host, port, client_kp, server_pub_key, ephemeral_key=ephemeral_key,
                                    application_key=application_key)

    async def connect(self, loop=None):
        await self.connection.connect(loop=loop)


class PSServer(PSSocket):
    def __init__(self, host, port, client_kp, application_key=None):
        self.connection = SHSServer(host, port, client_kp, application_key=application_key)

    async def listen(self, loop=None):
        await self.connection.listen(loop=loop)

    def on_connect(self, handler):
        async def _on_connect():
            await handler(self)
        self.connection._on_connect = _on_connect
