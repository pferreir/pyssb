import pytest
from asyncio import gather
from asynctest import patch
from nacl.signing import SigningKey

from ssb.packet_stream import PSClient, PSMessageType


async def _collect_messages(generator):
    results = []
    async for msg in generator:
        results.append(msg)
    return results

MSG_BODY_1 = (b'{"previous":"%KTGP6W8vF80McRAZHYDWuKOD0KlNyKSq6Gb42iuV7Iw=.sha256","author":"@1+Iwm79DKvVBqYKFkhT6fWRbA'
              b'VvNNVH4F2BSxwhYmx8=.ed25519","sequence":116,"timestamp":1496696699331,"hash":"sha256","content":{"type"'
              b':"post","channel":"crypto","text":"Does anybody know any good resources (e.g. books) to learn cryptogra'
              b'phy? I\'m not speaking of basic concepts (e.g. what\'s a private key) but the actual mathematics behind'
              b' the whole thing.\\nI have a copy of the \\"Handbook of Applied Cryptography\\" on my bookshelf but I f'
              b'ound it too long/hard to follow. Are there any better alternatives?","mentions":[]},"signature":"hqKePb'
              b'bTXWxEi1njDnOWFsL0M0AoNoWyBFgNE6KXj//DThepaZSy9vRbygDHX5uNmCdyOrsQrwZsZhmUYKwtDQ==.sig.ed25519"}')

MSG_BODY_2 = (b'{"previous":"%iQRhPyqmNLpGaO1Tpm1I22jqnUEwRwkCTDbwAGtM+lY=.sha256","author":"@1+Iwm79DKvVBqYKFkhT6fWRbA'
              b'VvNNVH4F2BSxwhYmx8=.ed25519","sequence":103,"timestamp":1496674211806,"hash":"sha256","content":{"type"'
              b':"post","channel":"git-ssb","text":"Is it only me or `git.scuttlebot.io` is timing out?\\n\\nE.g. try a'
              b'ccessing %vZCTqraoqKBKNZeATErXEtnoEr+wnT3p8tT+vL+29I4=.sha256","mentions":[{"link":"%vZCTqraoqKBKNZeATE'
              b'rXEtnoEr+wnT3p8tT+vL+29I4=.sha256"}]},"signature":"+i4U0HUGDDEyNoNr2NIROPnT3WQj3RuTaIhY5koWW8f0vwr4tZsY'
              b'mAkqqMwFWfP+eBIbc7DZ835er6r6h9CwAg==.sig.ed25519"}')


class MockConnection(object):
    def __init__(self):
        self.input = []
        self.output = []
        self.connected = False

    async def read(self):
        if not self.input:
            raise StopAsyncIteration
        return self.input.pop(0)

    def write(self, data):
        self.output.append(data)

    def feed(self, input):
        self.input += input

    def get_output(self):
        while True:
            if not self.output:
                break
            yield self.output.pop(0)

    async def disconnect(self):
        self.connected = False


@pytest.fixture
def ps_client(monkeypatch):
    def mock_connect():
        client._connected = True
        connection.connected = True
    client = PSClient('fake.local', 1000, SigningKey.generate(), b'\00' * 32)

    connection = MockConnection()
    monkeypatch.setattr(client, 'connect', mock_connect)
    monkeypatch.setattr(client, 'connection', connection)
    client.connect()

    return client, connection


@pytest.mark.asyncio
async def test_message_decoding(ps_client):
    client, connection = ps_client

    assert client.is_connected

    connection.feed([
        b'\n\x00\x00\x00\x9a\x00\x00\x04\xfb',
        b'{"name":["createHistoryStream"],"args":[{"id":"@omgyp7Pnrw+Qm0I6T6Fh5VvnKmodMXwnxTIesW2DgMg=.ed25519",'
        b'"seq":10,"live":true,"keys":false}],"type":"source"}'
    ])

    messages = (await _collect_messages(client))
    assert len(messages) == 1
    assert messages[0].type == PSMessageType.JSON
    assert messages[0].body == {
        'name': ['createHistoryStream'],
        'args': [
            {
                'id': '@omgyp7Pnrw+Qm0I6T6Fh5VvnKmodMXwnxTIesW2DgMg=.ed25519',
                'seq': 10,
                'live': True,
                'keys': False
            }
        ],
        'type': 'source'
    }


@pytest.mark.asyncio
async def test_message_encoding(ps_client):
    client, connection = ps_client

    assert client.is_connected

    client.send({
        'name': ['createHistoryStream'],
        'args': [{
            'id': "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519",
            'seq': 1,
            'live': False,
            'keys': False
        }],
        'type': 'source'
    }, stream=True)

    body = (b'{"name": ["createHistoryStream"], "args": [{"id": "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519"'
            b', "seq": 1, "live": false, "keys": false}], "type": "source"}')

    assert list(connection.get_output()) == [b'\x0a\x00\x00\x00\xa6\x00\x00\x00\x01', body]


@pytest.mark.asyncio
async def test_message_source(ps_client, mocker):
    client, connection = ps_client
    mocker.patch.object(client, 'register_handler', wraps=client.register_handler)

    assert client.is_connected

    client.send({
        'name': ['createHistoryStream'],
        'args': [{
            'id': "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519",
            'seq': 1,
            'live': False,
            'keys': False
        }],
        'type': 'source'
    }, stream=True)

    assert client.req_counter == 2
    assert client.register_handler.call_count == 1
    handler = list(client._event_map.values())[0][1]

    with patch.object(handler, 'process') as mock_process:
        connection.feed([b'\n\x00\x00\x02\xc5\xff\xff\xff\xff', MSG_BODY_1])
        msg = await client.read()
        assert mock_process.call_count == 1

        # responses have negative req
        assert msg.req == -1
        assert msg.body['previous'] == '%KTGP6W8vF80McRAZHYDWuKOD0KlNyKSq6Gb42iuV7Iw=.sha256'

        assert client.req_counter == 2

    stream_handler = client.send({
        'name': ['createHistoryStream'],
        'args': [{
            'id': "@1+Iwm79DKvVBqYKFkhT6fWRbAVvNNVH4F2BSxwhYmx8=.ed25519",
            'seq': 1,
            'live': False,
            'keys': False
        }],
        'type': 'source'
    }, stream=True)

    assert client.req_counter == 3
    assert client.register_handler.call_count == 2
    handler = list(client._event_map.values())[1][1]

    with patch.object(handler, 'process', wraps=handler.process) as mock_process:
        connection.feed([b'\n\x00\x00\x02\xc5\xff\xff\xff\xfe', MSG_BODY_1, b'\x0e\x00\x00\x023\xff\xff\xff\xfe',
                         MSG_BODY_2])

        # execute both message polling and response handling loops
        collected, handled = await gather(_collect_messages(client), _collect_messages(stream_handler))

        # No messages collected, since they're all responses
        assert collected == []

        assert mock_process.call_count == 2

        for msg in handled:
            # responses have negative req
            assert msg.req == -2
