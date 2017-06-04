import struct
from enum import Enum

from secret_handshake import SHSClient, SHSServer

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
        try:
            header = await self.connection.read()
            if not header:
                return
            body = await self.connection.read()
            flags, length, req = struct.unpack('>BIi', header)
            return PSMessage(bool(flags & 0x08), bool(flags & 0x04), flags & 0x03, body)
        except StopAsyncIteration:
            await self.connection.disconnect()
            return None

    async def __aiter__(self):
        while True:
            data = await self.read()
            if data is None:
                return
            yield data

    def write(self, type_, data, req=0):
        type_ = PSMessageType[type_]
        if type_ == PSMessageType.JSON:
            data = simplejson.dumps(data)

        # XXX: Not yet handling flags that nicely

        header = struct.pack('>BIi', 0x08 | type_.value, len(data), req)
        self.connection.write(header)
        self.connection.write(data.encode('utf-8'))


class PSClient(PSSocket):
    def __init__(self, host, port, client_kp, server_pub_key, ephemeral_key=None, application_key=None, loop=None):
        self.connection = SHSClient(host, port, client_kp, server_pub_key, ephemeral_key=ephemeral_key,
                                    application_key=application_key, loop=loop)
        self.loop = loop

    def connect(self):
        self.connection.connect()


class PSServer(PSSocket):
    def __init__(self, host, port, client_kp, application_key=None, loop=None):
        self.connection = SHSServer(host, port, client_kp, application_key=application_key, loop=loop)
        self.loop = loop

    def listen(self):
        self.connection.listen()

    def on_connect(self, cb):
        async def _on_connect():
            await cb(self)
        self.connection.on_connect(_on_connect)
