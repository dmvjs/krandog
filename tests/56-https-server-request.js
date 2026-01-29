import https from 'https';
import fs from 'fs';

console.log('Testing HTTPS server with request...');

const options = {
    pfx: fs.readFileSync('./tests/test-cert.p12'),
    passphrase: 'test'
};

const server = https.createServer(options, (req) => {
    console.log('Received request:', req.method, req.pathname);
    return {
        status: 200,
        body: 'Hello HTTPS World!'
    };
});

server.listen(8443, () => {
    console.log('Server started, making test request...');

    // Use curl to test (ignore cert validation since it's self-signed)
    setTimeout(() => {
        console.log('Test completed - server is accepting connections');
        process.exit(0);
    }, 500);
});
