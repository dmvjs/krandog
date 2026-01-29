# WebSocket Support in krandog

krandog includes full WebSocket support for both client and server implementations. The HTTP server automatically handles WebSocket upgrade requests, making it easy to build real-time applications.

## Table of Contents

- [Server-Side WebSocket](#server-side-websocket)
- [Client-Side WebSocket](#client-side-websocket)
- [Request Object Structure](#request-object-structure)
- [Complete Examples](#complete-examples)
- [WebSocket Protocol Details](#websocket-protocol-details)

## Server-Side WebSocket

The HTTP server automatically detects WebSocket upgrade requests and seamlessly switches to WebSocket protocol. No special configuration is needed!

### Basic Server Example

```javascript
import http from 'http';

const server = http.createServer((req) => {
    // Handle WebSocket messages
    if (req.type === 'websocket') {
        console.log('Received:', req.data);

        // Send response back to client
        req.ws.send('Echo: ' + req.data);

        // Don't return an HTTP response for WebSocket messages
        return;
    }

    // Handle regular HTTP requests
    return {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
        body: 'HTTP Server with WebSocket support'
    };
});

server.listen(3000);
```

### How It Works

1. Client sends HTTP request with `Upgrade: websocket` header
2. Server detects upgrade request and performs WebSocket handshake
3. Connection switches to WebSocket protocol
4. Subsequent messages from this connection arrive with `req.type === 'websocket'`
5. Use `req.ws.send()` to send messages back to the client

### Broadcasting to Multiple Clients

```javascript
import http from 'http';

const clients = [];

const server = http.createServer((req) => {
    if (req.type === 'websocket') {
        // Store new connections
        if (!clients.includes(req.ws)) {
            clients.push(req.ws);
            console.log('Client connected, total:', clients.length);
        }

        // Broadcast to all connected clients
        clients.forEach(client => {
            if (client.readyState === 1) { // 1 = OPEN
                client.send('Broadcast: ' + req.data);
            }
        });
        return;
    }

    return { status: 200, body: 'Broadcast Server' };
});

server.listen(3000);
```

## Client-Side WebSocket

krandog provides a WebSocket client implementation compatible with the browser WebSocket API.

The WebSocket client uses non-blocking sockets with kqueue event monitoring to properly handle connection timing. The client waits for the socket to become writable before sending the HTTP upgrade handshake.

### Basic Client Example

```javascript
const ws = new WebSocket('ws://example.com:3000');

ws.onopen = () => {
    console.log('Connected!');
    ws.send('Hello Server');
};

ws.onmessage = (event) => {
    console.log('Received:', event.data);
};

ws.onclose = () => {
    console.log('Connection closed');
};

ws.onerror = (error) => {
    console.error('Error:', error);
};
```

### Testing with External Clients

For reliable WebSocket testing, use external clients:

```bash
# Using wscat (npm install -g wscat)
wscat -c ws://localhost:3000

# Using websocat
websocat ws://localhost:3000
```

### WebSocket Client Methods

- **`ws.send(data)`** - Send a message to the server
  - `data` can be a string or buffer
- **`ws.close()`** - Close the connection gracefully

### WebSocket Client Properties

- **`ws.readyState`** - Connection state
  - `0` = CONNECTING
  - `1` = OPEN
  - `2` = CLOSING
  - `3` = CLOSED
- **`ws.url`** - The URL the WebSocket is connected to

### WebSocket Client Event Handlers

- **`ws.onopen`** - Called when connection is established
- **`ws.onmessage`** - Called when a message is received
  - Receives an event object with `event.data` containing the message
- **`ws.onclose`** - Called when connection is closed
- **`ws.onerror`** - Called when an error occurs

## Request Object Structure

When a WebSocket message arrives at your HTTP handler, the request object has the following structure:

```javascript
{
    type: "websocket",           // Identifies this as a WebSocket message

    ws: {                        // WebSocket connection object
        send(data),              // Send message to this client
        close(),                 // Close this connection
        readyState               // Connection state (1 = OPEN)
    },

    data: "message content",     // The actual message received (string)

    pathname: "/path",           // Original WebSocket connection path

    headers: {                   // Original HTTP upgrade request headers
        "upgrade": "websocket",
        "sec-websocket-key": "...",
        // ... other headers
    }
}
```

### Using the Request Object

```javascript
const server = http.createServer((req) => {
    if (req.type === 'websocket') {
        // Access the message
        console.log('Message:', req.data);

        // Send a response
        req.ws.send('Got your message: ' + req.data);

        // Check connection state
        if (req.ws.readyState === 1) {
            req.ws.send('Connection is open');
        }

        // Close the connection
        req.ws.close();

        return;
    }

    // ... handle HTTP requests
});
```

## Complete Examples

### Chat Server

See `examples/websocket-chat-server.js` for a complete chat server implementation with:
- Multiple client support
- Broadcasting messages
- User name management
- Web interface included

Run it:
```bash
./krandog examples/websocket-chat-server.js
# Open http://localhost:3000 in your browser
```

### Chat Client

See `examples/websocket-client.js` for a command-line WebSocket client example (note: may require external WebSocket client for reliable connections):

```bash
# Example script (demonstrates API usage)
./krandog examples/websocket-client.js ws://localhost:3000

# For reliable testing, use external clients
wscat -c ws://localhost:3000
```

## WebSocket Protocol Details

### Supported Features

- ✅ WebSocket handshake (Sec-WebSocket-Key → Sec-WebSocket-Accept)
- ✅ Frame encoding and decoding
- ✅ Client-to-server masking (required by protocol)
- ✅ TEXT frames (UTF-8 strings)
- ✅ BINARY frames (raw bytes)
- ✅ PING/PONG frames (automatic PONG responses)
- ✅ CLOSE frames (graceful connection termination)
- ✅ Non-blocking I/O via event loop

### Frame Types (Opcodes)

The implementation supports all standard WebSocket opcodes:

- **0x1: TEXT** - UTF-8 text messages
- **0x2: BINARY** - Binary data (buffers)
- **0x8: CLOSE** - Connection close frame
- **0x9: PING** - Ping frame (server auto-responds with PONG)
- **0xA: PONG** - Pong frame (response to PING)

### Protocol Compliance

The WebSocket implementation follows [RFC 6455](https://tools.ietf.org/html/rfc6455):

- Proper HTTP 101 Switching Protocols response
- SHA-1 hash of Sec-WebSocket-Key with magic GUID
- Base64 encoding of Sec-WebSocket-Accept
- Frame masking for client-to-server messages
- Frame unmasking for server processing

### Implementation Location

The WebSocket implementation is in `runtime.c`:

- **Lines 140-152**: WebSocket structure definition
- **Lines 3785-3877**: Frame encoding/decoding with masking
- **Lines 3994-4136**: Client-side WebSocket (`new WebSocket()`)
- **Lines 6037-6124**: Server-side upgrade handling
- **Lines 5700-5806**: Event loop integration

## Limitations and Future Enhancements

Current limitations:

- **No SSL/TLS support:** Only `ws://` protocol supported (not `wss://`)
- **Single-frame messages:** No fragmented message support
- **No compression:** permessage-deflate extension not implemented
- **No subprotocol negotiation:** Sec-WebSocket-Protocol not supported

These features may be added in future versions based on user needs.

## Testing

The test suite includes WebSocket tests:

- `tests/60-websocket-server.js` - Basic connection test
- `tests/61-websocket-echo.js` - Echo server with multiple messages
- `tests/62-websocket-broadcast.js` - Broadcasting to multiple clients

Run the tests:
```bash
./run-tests.sh
```

## Troubleshooting

### Connection Refused

If you get "Connection refused" errors:
- Ensure the server is running and listening on the correct port
- Check that you're using `ws://` not `wss://` (TLS not yet supported)
- Verify no firewall is blocking the port

### Messages Not Received

If messages aren't being received:
- Check that `req.type === 'websocket'` is being handled
- Verify you're not returning an HTTP response for WebSocket messages
- Ensure the connection is open (`ws.readyState === 1`)

### Connection Closes Immediately

If connections close right away:
- Don't return an HTTP response object for WebSocket messages
- Ensure your handler returns `undefined` or nothing for WebSocket messages
- Check for errors in your message handling code

## See Also

- [HTTP Server Documentation](http.md)
- [Examples Directory](../examples/)
- [RFC 6455 - The WebSocket Protocol](https://tools.ietf.org/html/rfc6455)
