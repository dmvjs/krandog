# websocket

http server automatically handles websocket upgrade requests.

## server

```javascript
import http from 'http';

const server = http.createServer((req) => {
    if (req.type === 'websocket') {
        req.ws.send('echo: ' + req.data);
        return;
    }
    return { status: 200, body: 'ok' };
});

server.listen(3000);
```

### request object

when websocket message arrives:

```javascript
{
    type: "websocket",
    ws: {
        send(data),      // send to client
        close(),         // close connection
        readyState       // 0=CONNECTING, 1=OPEN, 2=CLOSING, 3=CLOSED
    },
    data: "message",     // received message
    pathname: "/path",
    headers: {...}
}
```

### broadcasting

```javascript
const clients = [];

const server = http.createServer((req) => {
    if (req.type === 'websocket') {
        if (!clients.includes(req.ws)) {
            clients.push(req.ws);
        }

        clients.forEach(client => {
            if (client.readyState === 1) {
                client.send(req.data);
            }
        });
        return;
    }
    return { status: 200, body: 'ok' };
});
```

## client

```javascript
const ws = new WebSocket('ws://localhost:3000');

ws.onopen = () => {
    ws.send('hello');
};

ws.onmessage = (event) => {
    console.log(event.data);
};

ws.onclose = () => {
    console.log('closed');
};

ws.onerror = (error) => {
    console.error(error);
};
```

### methods

- `ws.send(data)` - send message
- `ws.close()` - close connection

### properties

- `ws.readyState` - 0=CONNECTING, 1=OPEN, 2=CLOSING, 3=CLOSED
- `ws.url` - connection url

## testing

```bash
# start server
./krandog examples/websocket-chat-server.js

# connect with wscat
wscat -c ws://localhost:3000

# or websocat
websocat ws://localhost:3000
```

## protocol

supports:
- text frames (utf-8 strings)
- binary frames
- ping/pong (auto-responds)
- close frames

follows rfc 6455:
- http 101 switching protocols
- sec-websocket-key/accept handshake
- frame masking (client to server)

## limitations

- no wss:// (ssl/tls)
- no fragmented messages
- no compression
- no subprotocol negotiation

## implementation

- runtime.c lines 140-152: websocket struct
- runtime.c lines 3785-3877: frame encoding/decoding
- runtime.c lines 3994-4136: client websocket
- runtime.c lines 5700-5806: event loop integration
- runtime.c lines 6037-6124: server upgrade handling
