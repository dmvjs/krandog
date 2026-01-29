// WebSocket Chat Server Example
// Demonstrates broadcasting messages to multiple connected clients
//
// Run: ./krandog examples/websocket-chat-server.js
// Connect with browser at: http://localhost:3000
// Or use external client: wscat -c ws://localhost:3000

import http from 'http';

const clients = new Map(); // Map of client connections
let clientIdCounter = 0;

console.log('🚀 WebSocket Chat Server Starting...');

const server = http.createServer((req) => {
    // Handle WebSocket messages
    if (req.type === 'websocket') {
        const ws = req.ws;

        // New connection - assign client ID
        if (!clients.has(ws)) {
            const clientId = ++clientIdCounter;
            clients.set(ws, { id: clientId, name: `User${clientId}` });

            console.log(`✅ Client ${clientId} connected (${clients.size} total)`);

            // Welcome the new client
            ws.send(JSON.stringify({
                type: 'welcome',
                id: clientId,
                message: `Welcome! You are User${clientId}`
            }));

            // Notify all other clients
            broadcast({
                type: 'join',
                user: `User${clientId}`,
                message: `User${clientId} joined the chat`
            }, ws);

            return;
        }

        // Handle incoming message
        const client = clients.get(ws);
        console.log(`💬 ${client.name}: ${req.data}`);

        try {
            const message = JSON.parse(req.data);

            // Handle name change
            if (message.type === 'setname') {
                const oldName = client.name;
                client.name = message.name;
                console.log(`📝 ${oldName} changed name to ${client.name}`);

                broadcast({
                    type: 'rename',
                    oldName: oldName,
                    newName: client.name,
                    message: `${oldName} is now ${client.name}`
                });
                return;
            }

            // Broadcast chat message
            if (message.type === 'message') {
                broadcast({
                    type: 'message',
                    user: client.name,
                    text: message.text,
                    timestamp: Date.now()
                });
                return;
            }
        } catch (e) {
            // Plain text message - treat as chat
            broadcast({
                type: 'message',
                user: client.name,
                text: req.data,
                timestamp: Date.now()
            });
        }

        return;
    }

    // Serve HTTP requests with a simple web interface
    if (req.method === 'GET' && req.pathname === '/') {
        return {
            status: 200,
            headers: { 'Content-Type': 'text/html' },
            body: `
<!DOCTYPE html>
<html>
<head>
    <title>krandog WebSocket Chat</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 50px auto; }
        #messages { border: 1px solid #ccc; height: 400px; overflow-y: auto; padding: 10px; margin: 20px 0; }
        .message { margin: 5px 0; }
        .system { color: #666; font-style: italic; }
        input { width: 80%; padding: 8px; }
        button { padding: 8px 20px; }
    </style>
</head>
<body>
    <h1>krandog WebSocket Chat</h1>
    <div id="status">Connecting...</div>
    <div id="messages"></div>
    <input id="input" type="text" placeholder="Type a message..." disabled>
    <button id="send" disabled>Send</button>

    <script>
        const ws = new WebSocket('ws://' + location.host);
        const messages = document.getElementById('messages');
        const input = document.getElementById('input');
        const status = document.getElementById('status');
        const sendBtn = document.getElementById('send');

        ws.onopen = () => {
            status.textContent = 'Connected';
            input.disabled = false;
            sendBtn.disabled = false;
            input.focus();
        };

        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            const div = document.createElement('div');
            div.className = 'message';

            if (msg.type === 'welcome') {
                div.className += ' system';
                div.textContent = msg.message;
            } else if (msg.type === 'join' || msg.type === 'rename') {
                div.className += ' system';
                div.textContent = msg.message;
            } else if (msg.type === 'message') {
                div.innerHTML = '<strong>' + msg.user + ':</strong> ' + msg.text;
            }

            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
        };

        ws.onclose = () => {
            status.textContent = 'Disconnected';
            input.disabled = true;
            sendBtn.disabled = true;
        };

        function sendMessage() {
            if (input.value) {
                ws.send(JSON.stringify({
                    type: 'message',
                    text: input.value
                }));
                input.value = '';
            }
        }

        sendBtn.onclick = sendMessage;
        input.onkeypress = (e) => {
            if (e.key === 'Enter') sendMessage();
        };
    </script>
</body>
</html>
            `
        };
    }

    // 404 for other routes
    return {
        status: 404,
        headers: { 'Content-Type': 'text/plain' },
        body: 'Not Found'
    };
});

// Helper function to broadcast to all clients
function broadcast(message, exclude = null) {
    const json = JSON.stringify(message);
    for (const [ws, client] of clients.entries()) {
        if (ws !== exclude && ws.readyState === 1) {
            ws.send(json);
        }
    }
}

// Handle client disconnections (when close frame received)
// Note: In the current implementation, we clean up when messages fail
// A future enhancement could add explicit disconnect handling

const PORT = 3000;
server.listen(PORT);
console.log(`💻 Chat server listening on http://localhost:${PORT}`);
console.log(`📡 WebSocket endpoint: ws://localhost:${PORT}`);
console.log('');
console.log('Open http://localhost:3000 in your browser to connect');
console.log('Or use the websocket-client.js example to connect via CLI');
