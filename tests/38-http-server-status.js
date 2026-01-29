// Test: HTTP server with status codes
serve(8002, (req) => {
    if (req.url === '/ok') {
        return { status: 200, body: 'success' };
    }
    return { status: 404, body: 'not found' };
});

console.log("Server with status codes started");

setTimeout(() => process.exit(0), 50);
