// Test: Basic HTTP server starts
serve(8001, (req) => {
    return { status: 200, body: 'hello' };
});

console.log("Server started successfully");

// Exit after a brief moment
setTimeout(() => process.exit(0), 50);
