from functools import wraps


class MuxRPCAPIException(Exception):
    pass


class MuxRPCRequest(object):
    @classmethod
    def from_message(cls, message):
        body = message.body
        return cls('.'.join(body['name']), body['args'])

    def __init__(self, name, args):
        self.name = name
        self.args = args

    def __repr__(self):
        return '<MuxRPCRequest {0.name} {0.args}>'.format(self)


class MuxRPCAPI(object):
    def __init__(self):
        self.handlers = {}
        self.connection = None

    async def __await__(self):
        async for req_message in self.connection:
            if req_message is None:
                return
            self.process(self.connection, MuxRPCRequest.from_message(req_message))

    def add_connection(self, connection):
        self.connection = connection

    def define(self, name):
        def _handle(f):
            self.handlers[name] = f

            @wraps(f)
            def _f(*args, **kwargs):
                return f(*args, **kwargs)
            return f
        return _handle

    def process(self, connection, request):
        handler = self.handlers.get(request.name)
        if not handler:
            raise MuxRPCAPIException('Method {} not found!'.format(request.name))
        handler(connection, request)
