// WebSocket Client Example
// Demonstrates connecting to a WebSocket server and sending/receiving messages
//
// Note: The built-in WebSocket client may have connection timing issues.
// For reliable testing, use external clients like wscat or websocat.
//
// Run: ./krandog examples/websocket-client.js ws://localhost:3000

// Get URL from command line or use default
const url = process.argv[2] || 'ws://localhost:3000';

console.log('🔌 Connecting to', url);

const ws = new WebSocket(url);

ws.onopen = () => {
    console.log('✅ Connected!');
    console.log('');
    console.log('Type messages and press Enter to send.');
    console.log('Messages from the server will appear here.');
    console.log('Press Ctrl+C to disconnect.');
    console.log('');

    // Send a test message
    ws.send(JSON.stringify({
        type: 'message',
        text: 'Hello from krandog WebSocket client!'
    }));
};

ws.onmessage = (event) => {
    try {
        const msg = JSON.parse(event.data);

        if (msg.type === 'welcome') {
            console.log(`💬 ${msg.message}`);
        } else if (msg.type === 'join') {
            console.log(`📥 ${msg.message}`);
        } else if (msg.type === 'rename') {
            console.log(`📝 ${msg.message}`);
        } else if (msg.type === 'message') {
            const time = new Date(msg.timestamp).toLocaleTimeString();
            console.log(`[${time}] ${msg.user}: ${msg.text}`);
        } else {
            console.log('📨', event.data);
        }
    } catch (e) {
        // Plain text message
        console.log('📨', event.data);
    }
};

ws.onerror = (error) => {
    console.error('❌ WebSocket error:', error);
};

ws.onclose = () => {
    console.log('');
    console.log('🔌 Disconnected from server');
    process.exit(0);
};

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('');
    console.log('👋 Closing connection...');
    ws.close();
});

// Note: In a full implementation, you would set up stdin reading here
// to allow interactive message sending. This example demonstrates the
// WebSocket connection and automatic message handling.
//
// Example of how to send messages:
// - ws.send('Plain text message')
// - ws.send(JSON.stringify({ type: 'message', text: 'Formatted message' }))
// - ws.send(JSON.stringify({ type: 'setname', name: 'NewUsername' }))

// Send a few test messages to demonstrate
setTimeout(() => {
    ws.send(JSON.stringify({
        type: 'message',
        text: 'This is a test message from the client'
    }));
}, 1000);

setTimeout(() => {
    ws.send(JSON.stringify({
        type: 'message',
        text: 'WebSocket communication working perfectly! 🎉'
    }));
}, 2000);

// Keep the process alive
setTimeout(() => {
    console.log('');
    console.log('✨ Test complete. Press Ctrl+C to exit or leave running to see other messages.');
}, 3000);
