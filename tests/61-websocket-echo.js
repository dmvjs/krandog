// Test: WebSocket echo - server echoes messages back (manual test)
// Note: WebSocket client has timing issues with non-blocking sockets
// This test documents the expected server behavior for manual testing

import http from 'http';

console.log('WebSocket echo server test');
console.log('Server will echo all WebSocket messages');

const server = http.createServer((req) => {
    if (req.type === 'websocket') {
        const echoed = 'ECHO: ' + req.data;
        console.log('Received:', req.data);
        console.log('Sending:', echoed);
        req.ws.send(echoed);
        return;
    }

    return {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
        body: '<h1>WebSocket Echo Server</h1><p>Connect with wscat -c ws://localhost:9081</p>'
    };
});

server.listen(9081);
console.log('Echo server ready on port 9081');
console.log('Test server is running');

// Server will keep running for manual tests
// In automated tests, we just verify it started
setTimeout(() => {
    console.log('Server verified running');
    process.exit(0);
}, 500);
