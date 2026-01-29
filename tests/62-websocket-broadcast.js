// Test: WebSocket broadcast functionality (manual test)
// Server broadcasts messages to all connected clients

import http from 'http';

console.log('WebSocket broadcast server test');

const clients = [];

const server = http.createServer((req) => {
    if (req.type === 'websocket') {
        // Track new connections
        if (!clients.includes(req.ws)) {
            clients.push(req.ws);
            console.log('Client connected, total:', clients.length);
        }

        // Broadcast to all clients
        console.log('Broadcasting:', req.data);
        let broadcast_count = 0;
        clients.forEach(client => {
            if (client.readyState === 1) {
                client.send('Broadcast: ' + req.data);
                broadcast_count++;
            }
        });
        console.log('Sent to', broadcast_count, 'clients');
        return;
    }

    return {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
        body: '<h1>WebSocket Broadcast Server</h1><p>Messages are broadcast to all connected clients</p>'
    };
});

server.listen(9082);
console.log('Broadcast server ready on port 9082');
console.log('Server supports multiple concurrent clients');

setTimeout(() => {
    console.log('Test complete');
    process.exit(0);
}, 500);
