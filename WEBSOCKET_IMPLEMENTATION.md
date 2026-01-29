# websocket implementation

websocket server was already implemented in runtime.c. this work added tests, examples, and documentation.

## tests

- tests/60-websocket-server.js - server starts
- tests/61-websocket-echo.js - echo behavior
- tests/62-websocket-broadcast.js - broadcast functionality

all pass.

## examples

- examples/websocket-chat-server.js - chat server with web interface
- examples/websocket-client.js - command line client

## documentation

- docs/websocket.md - api reference and usage

## server features

- automatic websocket upgrade (detects `Upgrade: websocket` header)
- text/binary/ping/pong/close frames
- frame masking per rfc 6455
- non-blocking io via kqueue
- `req.type === 'websocket'` for messages
- `req.ws.send()` to reply
- `req.ws.close()` to close

## client fix (2026-01-29)

websocket client had timing bug with non-blocking sockets. fixed by:

- added `handshake_buffer` and `handshake_len` to WebSocket struct
- register EVFILT_WRITE to detect when socket is writable
- send handshake only after write event fires
- switch to EVFILT_READ after handshake sent

## limitations

- no wss:// (no tls)
- no message fragmentation
- no compression extensions
- no subprotocol negotiation

## implementation location

runtime.c:
- lines 140-152: struct definition
- lines 3785-3877: frame encoding/decoding
- lines 3994-4136: client
- lines 5700-5806: event loop
- lines 6037-6124: server upgrade

## files added

- tests/60-websocket-server.js + .expected
- tests/61-websocket-echo.js + .expected
- tests/62-websocket-broadcast.js + .expected
- examples/websocket-chat-server.js
- examples/websocket-client.js
- docs/websocket.md

no changes to runtime.c for initial documentation (websocket was already working).
client fix required runtime.c changes.
