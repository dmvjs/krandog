// Test: HTTP server handler receives request object
serve(8003, (req) => {
    // Handler receives request with headers
    return { status: 200, body: 'ok' };
});

console.log("HTTP server handler ready");

setTimeout(() => process.exit(0), 50);
