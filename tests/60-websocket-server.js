// Test: WebSocket-capable HTTP server starts successfully
import http from 'http';

console.log('Testing WebSocket-capable HTTP server');

const server = http.createServer((req) => {
    // Handle WebSocket messages
    if (req.type === 'websocket') {
        console.log('WebSocket message:', req.data);
        req.ws.send('Echo: ' + req.data);
        return;
    }

    // Handle HTTP requests
    return {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
        body: 'Server is running'
    };
});

server.listen(9080);
console.log('Server started on port 9080');
console.log('Server can handle both HTTP and WebSocket');

// Test passes if server starts without errors
setTimeout(() => {
    console.log('Test complete');
    process.exit(0);
}, 200);
