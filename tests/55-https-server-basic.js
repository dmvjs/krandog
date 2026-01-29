// Test: Basic HTTPS server starts
import https from 'https';
import fs from 'fs';

const options = {
    pfx: fs.readFileSync('./tests/test-cert.p12'),
    passphrase: 'test'
};

const server = https.createServer(options, (req) => {
    return { status: 200, body: 'Hello HTTPS!' };
});

server.listen(8443, () => {
    console.log('HTTPS server started successfully');
    setTimeout(() => process.exit(0), 50);
});
