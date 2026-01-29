// Test: HTTPS server with custom response
import https from 'https';
import fs from 'fs';

const options = {
    pfx: fs.readFileSync('./tests/test-cert.p12'),
    passphrase: 'test'
};

const server = https.createServer(options, (req) => {
    return {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
        body: '{"message":"Hello HTTPS"}'
    };
});

server.listen(8444, () => {
    console.log('HTTPS server with custom response ready');
    setTimeout(() => process.exit(0), 50);
});
